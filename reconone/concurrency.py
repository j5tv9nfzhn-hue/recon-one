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
from urllib.parse import urljoin, urlsplit

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


def _needs_serial(session) -> bool:
    """Does the run carry state the httpx fast path cannot reproduce?

    Proxy routing (especially SOCKS5) and pacing are implemented in `http.Session`, not in
    httpx. When either is active, correctness wins: run the batch through `session.request`
    so the request cannot silently take a different route or ignore `--rate`.
    """
    egress = getattr(session, "egress", None)
    if egress is not None and (egress.proxy is not None or egress.fallback is not None):
        return True
    limiter = getattr(session, "limiter", None)
    if limiter is not None and (getattr(limiter, "rate", 0) > 0 or limiter.throttled > 0):
        return True
    return False


def _request_headers(session, url: str, extra: dict | None) -> dict:
    """Same header contract as `Session._attempt`: injected identity + jar, one Cookie."""
    hdrs = {
        "User-Agent": session.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.8",
    }
    if extra:
        hdrs.update(extra)
    hdrs = session.injection.apply(hdrs)
    parts = urlsplit(url)
    cookie = session._cookie_header(parts.hostname or "", parts.path or "/",
                                    parts.scheme == "https", hdrs)
    hdrs = {name: value for name, value in hdrs.items() if name.lower() != "cookie"}
    if cookie:
        hdrs["Cookie"] = cookie
    return hdrs


async def _one(client, session, budget_lock, url, method, data, headers, max_bytes):
    """单个 URL（含重定向链）。返回 (url, Response)。异常一律转成带原因的 Response。

    这条路径与 `Session.request` 保持同一套纪律：作用域先于请求、注入头与 cookie jar、
    逐 host 限速、重定向每一跳都过作用域、预算原子预占、失败也写台账。
    代理/限速场景由 `_needs_serial()` 直接交回串行路径，避免 httpx 走出另一条路由。
    """
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

    current = url
    current_method = method
    current_data = data
    chain: list[str] = []
    total_read = 0
    hop_started = time.time()
    try:
        for _hop in range(6):
            if not session.in_scope(current):
                session.off_scope_attempts.append(current)
                return current, Response(current, error="out_of_scope: blocked by policy")
            if total_read >= limit:
                return current, Response(current, error="budget_exhausted: redirect chain "
                                                       "exceeded the byte cap")
            parts = urlsplit(current)
            host = parts.hostname or ""
            secure = parts.scheme == "https"
            hop_started = time.time()
            waited = session.limiter.before(host, deadline=session.deadline)
            async with client.stream(current_method, current, content=current_data,
                                     headers=_request_headers(session, current, headers)) as resp:
                remaining = max(0, limit - total_read)
                chunks, total = [], 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total >= remaining:
                        chunks.append(chunk[: max(0, remaining - (total - len(chunk)))])
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
                total_read += len(body)
                elapsed = int((time.time() - hop_started) * 1000)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = [value for name, value in resp.headers.multi_items()
                           if name.lower() == "set-cookie"]
                if cookies:
                    session.cookies.store(host, parts.path or "/", secure, cookies)
                session.limiter.after(host, resp.status_code, resp_headers)
                # 规则 2：预算累加必须原子
                async with budget_lock:
                    session.requests += 1
                    session.bytes_total += len(body)
                    if session.bytes_total >= session.max_total_bytes:
                        session.exhausted = True
                    session.log.append({
                        "url": current, "status": resp.status_code, "bytes": len(body),
                        "ms": elapsed, "method": current_method, "egress": "direct",
                        "wait_ms": int(waited * 1000),
                    })
                chain.append(current)
                location = resp_headers.get("location")
                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    nxt = urljoin(current, location)
                    if resp.status_code == 303:
                        current_method, current_data = "GET", None
                    current = nxt
                    continue
                return current, Response(current, resp.status_code, resp_headers, body, elapsed,
                                         redirect_chain=chain,
                                         truncated=total_read >= limit)
        return current, session._fail(current, "redirect_limit", "more than 5 redirects")
    except Exception as exc:                       # 规则 3：只影响自己
        kind = "timeout" if "timeout" in type(exc).__name__.lower() else "connect"
        async with budget_lock:
            session.requests += 1
            session.log.append({"url": current, "status": 0, "bytes": 0,
                                "ms": int((time.time() - hop_started) * 1000),
                                "method": current_method, "egress": "direct", "error": kind})
        return current, session._fail(current, kind, f"{type(exc).__name__}: {exc}")
    finally:
        async with budget_lock:
            session.reserved_bytes = max(0, getattr(session, "reserved_bytes", 0) - grant)


async def _gather(session, jobs, degree, cancel):
    results: dict[int, Response] = {}
    lock = anyio.Lock()
    limiter = anyio.CapacityLimiter(degree)
    timeout = httpx.Timeout(session.timeout or 12.0, connect=min(6.0, session.timeout or 12.0))

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=session.verify_tls,
        follow_redirects=False,          # 重定向由调用方决定，与串行路径保持一致
        # Egress is `Session`'s job. Environment proxies here would silently contradict
        # `--direct`/`--proxy`; the caller falls back to the serial path when a proxy is set.
        trust_env=False,
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


def _serial(session, jobs) -> list[Response]:
    return [session.request(j["url"], method=j.get("method", "GET"), data=j.get("data"),
                            headers=j.get("headers"), max_bytes=j.get("max_bytes"),
                            follow=j.get("follow", True))
            for j in jobs]


def fetch_many(session, jobs, degree: int = DEFAULT_PARALLEL, cancel=None) -> list[Response]:
    """并行抓取，返回与 `jobs` **同序**的 Response 列表。

    同序是刻意的：报告里的端点顺序不能因为并发而抖动，否则两次扫描的 diff
    全是噪音，也没法用「逐字段相同」来验证并发化的正确性。

    代理与限速启用时退回串行：那条路径的每一条纪律（CONNECT/SOCKS5、`Retry-After`）
    由 `Session` 实现，httpx 快速路径不会替我们遵守。
    """
    if not jobs:
        return []
    if _needs_serial(session):
        return _serial(session, jobs)
    degree = parallel_degree(session, degree)
    if degree <= 1:
        return _serial(session, jobs)

    try:
        import asyncio
        results = asyncio.run(_gather(session, jobs, degree, cancel))
    except RuntimeError:
        # 已经在事件循环里（被别的异步宿主调用）—— 退回串行，结果形状不变
        return _serial(session, jobs)
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
