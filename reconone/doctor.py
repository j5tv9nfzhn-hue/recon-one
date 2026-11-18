"""Runtime proof that the hard dependencies actually work, not just that they import.

Why this exists
---------------
`import httpx` succeeding says nothing about whether a client can be constructed in this
environment (broken wheels, missing `ssl` bindings and stripped-down interpreters all pass
the import and fail at the first request). The scanner is a multi-minute operation, so the
question "is the floor solid" has to be answerable in one second, separately from a scan.

What it does *not* do
---------------------
* No network. Nothing here resolves a name or opens a socket to a remote host.
* No writing outside the project: only ``os.access`` and in-memory objects.
* No AI, no heuristics: each check is one assertion with the exception text kept.

Exit code follows the rest of the tool: ``0`` = floor is solid, ``4`` = unusable dependency
(the same code `python -m reconone` uses when an import is missing).
"""
from __future__ import annotations

import platform
import ssl
import sys
import traceback
from importlib import metadata

OK = "ok"
BAD = "bad"

#: Packages the scanner cannot run without. Kept in sync with ``requirements.txt``.
REQUIRED = ("httpx", "anyio")


def versions() -> dict:
    """Installed versions, read from package metadata. Never raises."""
    out = {"python": platform.python_version(), "ssl": ssl.OPENSSL_VERSION.split(" ")[0]}
    for name in REQUIRED:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = ""
        except Exception:                       # noqa: BLE001 - metadata is best-effort
            out[name] = ""
    return out


def _check(cid: str, title: str, fn) -> dict:
    try:
        detail = fn()
    except Exception as exc:                    # noqa: BLE001 - the report is the product
        return {"id": cid, "title": title, "ok": False,
                "detail": f"{type(exc).__name__}: {exc}"[:300],
                "trace": traceback.format_exc(limit=3)[-600:]}
    return {"id": cid, "title": title, "ok": True, "detail": str(detail)[:300]}


# --------------------------------------------------------------------------- checks
def _python() -> str:
    if sys.version_info < (3, 9):
        raise RuntimeError(f"python {platform.python_version()} < 3.9")
    return f"python {platform.python_version()}"


def _httpx_client() -> str:
    import httpx

    # Constructing a client is the real dependency: a broken/flat ssl module fails here,
    # not on import. It opens no connection.
    with httpx.Client(timeout=1.0, follow_redirects=False) as client:
        limits = client._transport  # noqa: SLF001 - existence is the assertion
        if limits is None:
            raise RuntimeError("transport missing")
    return f"httpx {httpx.__version__} client ok"


def _anyio_taskgroup() -> str:
    import anyio

    async def work() -> list[int]:
        order: list[int] = []
        limiter = anyio.CapacityLimiter(2)

        async def one(index: int) -> None:
            async with limiter:
                order.append(index)

        async with anyio.create_task_group() as tg:
            for index in range(4):
                tg.start_soon(one, index)
        return order

    order = anyio.run(work)
    if sorted(order) != [0, 1, 2, 3]:
        raise RuntimeError(f"task group lost work: {order}")
    return f"anyio {metadata.version('anyio')} taskgroup+limiter ok"


def _dns_socket() -> str:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.2)
    finally:
        sock.close()
    # IPv6 is optional on some hosts; probe it but do not fail the whole check on it.
    try:
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock6.close()
        extra = "ipv4+ipv6"
    except OSError:
        extra = "ipv4 only"
    return f"dns udp socket ok ({extra})"


def _ssl_context() -> str:
    ctx = ssl.create_default_context()
    if ctx.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError("default context does not verify certificates")
    return f"{ssl.OPENSSL_VERSION} verify=required"


CHECKS = (
    ("deps.python", "Python 运行时", _python),
    ("deps.httpx", "httpx 客户端可构造", _httpx_client),
    ("deps.anyio", "anyio TaskGroup + 限流器", _anyio_taskgroup),
    ("deps.dns", "DNS UDP 套接字", _dns_socket),
    ("deps.ssl", "TLS 默认上下文（校验证书）", _ssl_context),
)


def run() -> dict:
    """Run every check. Pure function of the installed environment."""
    checks = [_check(cid, title, fn) for cid, title, fn in CHECKS]
    return {"version": 1, "ok": all(c["ok"] for c in checks),
            "versions": versions(), "checks": checks,
            "generated_by": "reconone.doctor (local runtime checks, no network, no AI)"}


def summary(result: dict) -> str:
    """One line for the CLI: how many passed, and which failed."""
    failed = [c["id"] for c in result.get("checks") or [] if not c["ok"]]
    total = len(result.get("checks") or [])
    if not failed:
        v = result.get("versions") or {}
        return (f"{total}/{total} 通过 · python {v.get('python', '?')} · "
                f"httpx {v.get('httpx', '?')} · anyio {v.get('anyio', '?')}")
    return f"{total - len(failed)}/{total} 通过 · 失败：{', '.join(failed)}"
