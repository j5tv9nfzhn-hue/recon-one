"""并发抓取层。

这是「引入第三方库」这件事真正的落点：把串行的等待叠起来，同时**不放松**
原有 Session 的任何一条纪律。

三条不可协商的规则（见 docs/third-party-libs.md §2）：

1. 作用域闸门在并发层**之前**。不过闸门的 URL 根本不进入任务组。
2. 字节预算是共享的原子量。多个协程同时累加必须加锁，否则 40MB 上限会被突破 N 倍。
3. 失败不等于通过。单个分支失败只把它自己标成失败，**不得**污染同批其它结果，
   更不得把「没拿到」当成「没有」。

依赖：httpx（HTTP 客户端）、anyio（TaskGroup + CapacityLimiter）。两者都是**硬依赖**，
已写进 requirements.txt，缺失时本模块在 import 阶段就抛错（`cli` 会先给一句可执行的提示，
而不是丢一个 traceback）。串行仍保留，但只作为「并发度=1」的预算决策，不再是缺库兜底。
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

import anyio
import httpx

from .http import Response

HAVE_HTTPX = True       # 保留这个常量供调用方判断，但依赖已是必装


DEFAULT_PARALLEL = 6
HARD_CAP = 8                            # 对单个目标的并行上限，超过只会更快被 WAF 盯上


def parallel_degree(session, requested: int = DEFAULT_PARALLEL, per_request: float = 0.0) -> int:
    """并发度不是拍脑袋定的，由预算决定。

    min( 硬上限, 用户请求值, 时间预算能容纳的并发数 )
    """
    n = max(1, min(int(requested), HARD_CAP))
    if session.deadline:
        left = session.deadline - time.time()
        if left <= 0:
            return 1
        each = per_request or session.timeout or 12.0
        n = max(1, min(n, int(left // max(each, 0.1)) or 1))
    return n


def _cancelled(cancel) -> bool:
    """同时兼容 threading.Event 与可调用谓词 —— 这里踩过坑，别再假设它是函数。"""
    if cancel is None:
        return False
    if callable(cancel):
        return bool(cancel())
    is_set = getattr(cancel, "is_set", None)
    return bool(is_set()) if callable(is_set) else False


def _headers(session, extra: dict | None) -> dict:
    hdrs = {
        "User-Agent": session.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.8",
    }
    if extra:
        hdrs.update(extra)
    return hdrs


async def _one(client, session, budget_lock, url, method, data, headers, max_bytes):
    """单个 URL。返回 (url, Response)。异常一律转成带原因的 Response，绝不外抛。"""
    # 规则 1：闸门在前
    if not session.in_scope(url):
        session.off_scope_attempts.append(url)
        return url, Response(url, error="out_of_scope: blocked by policy")
    limit = max_bytes or session.max_body
    # 规则 2 的落实：先"预占"再派发。可用额 = 上限 - 已用 - 在途。
    async with budget_lock:
        if not session.budget_left():
            return url, Response(url, error="budget_exhausted: byte or time cap reached")
        room = session.max_total_bytes - session.bytes_total - getattr(session, "reserved_bytes", 0)
        if room <= 0:
            return url, Response(url, error="budget_exhausted: byte cap reserved by in-flight requests")
        grant = min(limit, room)
        session.reserved_bytes = getattr(session, "reserved_bytes", 0) + grant
        limit = grant
    started = time.time()
    try:
        async with client.stream(method, url, content=data, headers=_headers(session, headers)) as resp:
            chunks, total = [], 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total >= limit:
                    chunks.append(chunk[: max(0, limit - (total - len(chunk)))])
                    break
                chunks.append(chunk)
            body = b"".join(chunks)
            elapsed = int((time.time() - started) * 1000)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            # 规则 2：预算累加必须原子
            async with budget_lock:
                session.reserved_bytes = max(0, getattr(session, "reserved_bytes", 0) - grant)
                session.requests += 1
                session.bytes_total += len(body)
                if session.bytes_total >= session.max_total_bytes:
                    session.exhausted = True
                session.log.append({"url": url, "status": resp.status_code,
                                    "bytes": len(body), "ms": elapsed, "method": method})
            return url, Response(url, resp.status_code, hdrs, body, elapsed,
                                 truncated=total >= limit)
    except Exception as exc:                       # 规则 3：只影响自己
        async with budget_lock:
            session.reserved_bytes = max(0, getattr(session, "reserved_bytes", 0) - grant)
            session.requests += 1
        kind = "timeout" if "timeout" in type(exc).__name__.lower() else "connect"
        return url, session._fail(url, kind, f"{type(exc).__name__}: {exc}")


async def _gather(session, jobs, degree, cancel):
    results: dict[int, Response] = {}
    lock = anyio.Lock()
    limiter = anyio.CapacityLimiter(degree)
    timeout = httpx.Timeout(session.timeout or 12.0, connect=min(6.0, session.timeout or 12.0))

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=session.verify_tls,
        follow_redirects=False,          # 重定向由调用方决定，与串行路径保持一致
        limits=httpx.Limits(max_connections=degree, max_keepalive_connections=degree),
    ) as client:
        async def run(idx, job):
            if _cancelled(cancel):
                results[idx] = Response(job["url"], error="cancelled")
                return
            async with limiter:
                _, resp = await _one(client, session, lock, job["url"], job.get("method", "GET"),
                                     job.get("data"), job.get("headers"), job.get("max_bytes"))
                results[idx] = resp

        async with anyio.create_task_group() as tg:
            for idx, job in enumerate(jobs):
                tg.start_soon(run, idx, job)
    return results


def fetch_many(session, jobs, degree: int = DEFAULT_PARALLEL, cancel=None) -> list[Response]:
    """并行抓取，返回与 `jobs` **同序**的 Response 列表。

    同序是刻意的：报告里的端点顺序不能因为并发而抖动，否则两次扫描的 diff
    全是噪音，也没法用「逐字段相同」来验证并发化的正确性。
    """
    if not jobs:
        return []
    degree = parallel_degree(session, degree)
    if degree <= 1:
        return [session.request(j["url"], method=j.get("method", "GET"), data=j.get("data"),
                                headers=j.get("headers"), max_bytes=j.get("max_bytes"),
                                follow=j.get("follow", True))
                for j in jobs]

    try:
        import asyncio
        results = asyncio.run(_gather(session, jobs, degree, cancel))
    except RuntimeError:
        # 已经在事件循环里（被别的异步宿主调用）—— 退回串行，结果形状不变
        return [session.request(j["url"], method=j.get("method", "GET"), data=j.get("data"),
                                headers=j.get("headers"), max_bytes=j.get("max_bytes"))
                for j in jobs]
    return [results.get(i) or Response(j["url"], error="not_executed: worker did not run")
            for i, j in enumerate(jobs)]


def probe_many(session, base_url: str, paths, method: str = "GET", data=None,
               headers: dict | None = None, max_bytes: int | None = None,
               limit: int | None = None, cancel=None) -> list[tuple[str, Response]]:
    """按 path 列表批量探测，返回 [(url, Response)]。

    用于 OpenAPI 候选路径、GraphQL 候选路径这类「纯等待、彼此无依赖」的探测。
    """
    root = base_url.rstrip("/")
    paths = list(paths)
    if limit:
        paths = paths[:limit]
    jobs = [{"url": root + (p if p.startswith("/") else "/" + p), "method": method,
             "data": data, "headers": headers, "max_bytes": max_bytes} for p in paths]
    resps = fetch_many(session, jobs, cancel=cancel)
    return [(j["url"], r) for j, r in zip(jobs, resps)]
