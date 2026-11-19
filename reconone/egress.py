"""Egress: which proxy a request leaves through, and what to do when direct fails.

Why this module exists
----------------------
The transport is `http.client`, i.e. direct connections. Two consequences showed up in
practice:

* on networks where the target is only reachable through a proxy (corporate egress, or a
  site that blocks the residential IP), every stage times out and the report reads
  `unreachable` — which is honest, but useless;
* a transient timeout is indistinguishable from "this host is filtered", so the operator
  cannot tell whether to retry, change egress, or give up.

This module gives the session three things: a **manual** proxy (`--proxy`), the **system**
proxy (WinINET/`HTTP(S)_PROXY`), and an **auto fallback**: try direct, and if the failure
is a connect timeout/reset/refusal, retry the same request once through the system proxy and
record that it happened. Nothing is guessed: the report says which route was used and how
many requests needed the fallback.

Supported routes
----------------
``http://host:port``   absolute-URI forwarding for http, CONNECT tunnel for https
``socks5://host:port`` minimal SOCKS5 CONNECT (no auth, or user/pass) — implemented here so
                       it needs no extra dependency
``direct``             today's behaviour

What this module deliberately does *not* do: PAC script evaluation. A PAC URL is reported as
`pac: true, pac_supported: false` instead of being silently ignored, because "we used the
wrong proxy" and "we used no proxy" are different failures.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
import struct
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from .util import redact_url

SUPPORTED_SCHEMES = ("http", "https", "socks5", "socks5h")
ENV_KEYS = ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy")


# --------------------------------------------------------------------------- model
@dataclass(frozen=True)
class Proxy:
    """One parsed proxy endpoint. Credentials stay in memory, never in the report."""

    scheme: str = ""
    host: str = ""
    port: int = 0
    user: str = ""
    password: str = ""

    @property
    def is_socks(self) -> bool:
        return self.scheme in ("socks5", "socks5h")

    @property
    def auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.user else None

    def basic_header(self) -> dict:
        if not self.user:
            return {}
        raw = f"{self.user}:{self.password}".encode()
        return {"Proxy-Authorization": "Basic " + base64.b64encode(raw).decode()}

    def describe(self) -> str:
        """Host:port only — the report records the route, not the credential."""
        return f"{self.host}:{self.port}" if self.host else ""


def parse_proxy(url: str) -> Proxy:
    """Parse one proxy URL. Raises ValueError on an unusable value (caller reports it)."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("empty proxy")
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported proxy scheme: {scheme or '?'}")
    host = parts.hostname or ""
    if not host:
        raise ValueError("proxy has no host")
    port = parts.port or (1080 if scheme.startswith("socks") else 8080)
    return Proxy(scheme=scheme, host=host, port=int(port),
                 user=unquote(parts.username or ""), password=unquote(parts.password or ""))


def _windows_proxy() -> tuple[str, bool, str]:
    """Read the WinINET (per-user) proxy setting. Returns (proxy, pac, source)."""
    try:
        import winreg  # noqa: PLC0415 - Windows only, imported lazily
    except ImportError:
        return "", False, ""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        with key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            try:
                pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            except OSError:
                pac = ""
    except OSError:
        return "", False, ""
    if pac and not enabled:
        # A PAC script is the real configuration; we cannot evaluate it, so say so.
        return "", True, "wininet-pac"
    if not enabled or not server:
        return "", False, ""
    # `ProxyServer` can be per-protocol: "http=1.2.3.4:80;https=1.2.3.4:443"
    chosen = ""
    for chunk in str(server).split(";"):
        name, _, value = chunk.partition("=")
        if name.strip().lower() in ("https", "http") and value.strip():
            chosen = value.strip()
            if name.strip().lower() == "https":
                break
    return (chosen or str(server).split(";")[0]), False, "wininet"


def system_proxy() -> tuple[str, str, bool]:
    """Best available system proxy. Returns (url, source, pac_unsupported)."""
    for key in ENV_KEYS:
        value = os.environ.get(key, "").strip()
        if value:
            return value, f"env:{key}", False
    url, pac, source = _windows_proxy()
    return url, source, pac


# --------------------------------------------------------------------------- policy
@dataclass(frozen=True)
class Egress:
    """How this run leaves the machine. `fallback` is only used for auto mode."""

    mode: str = "auto"          # auto | direct | manual | system
    proxy: Proxy | None = None
    fallback: Proxy | None = None
    source: str = ""
    no_proxy: tuple[str, ...] = field(default_factory=tuple)
    pac_ignored: bool = False

    # -- selection -------------------------------------------------------------
    def bypass(self, host: str) -> bool:
        host = (host or "").lower()
        for suffix in self.no_proxy:
            suffix = suffix.strip().lower().lstrip(".")
            if suffix and (host == suffix or host.endswith("." + suffix)):
                return True
        return False

    def route_for(self, host: str) -> Proxy | None:
        """Primary route for *host*: None means direct."""
        if self.bypass(host):
            return None
        return self.proxy

    def fallback_for(self, host: str) -> Proxy | None:
        if self.bypass(host):
            return None
        return self.fallback

    # -- reporting -------------------------------------------------------------
    def view(self, fallback_count: int = 0, requests: int = 0) -> dict:
        primary = self.proxy
        return {
            "mode": self.mode,
            "type": ("socks5" if primary and primary.is_socks else
                     ("http" if primary else "direct")),
            "host": primary.describe() if primary else "",
            "source": self.source,
            "fallback": bool(self.fallback),
            "fallback_used": int(fallback_count),
            "fallback_requests_pct": (round(fallback_count / requests * 100.0, 1)
                                      if requests else 0.0),
            "no_proxy": list(self.no_proxy),
            "pac": {"detected": bool(self.pac_ignored), "supported": False},
        }

    def label(self) -> str:
        if not self.proxy:
            return "直连"
        return f"{'socks5' if self.proxy.is_socks else 'http'}://{self.proxy.describe()}"


def resolve(mode: str = "auto", proxy: str = "", no_proxy: str | tuple = ()) -> Egress:
    """Build the egress policy.

    ``mode``:
      * ``auto``   — direct, with the system proxy as a one-shot fallback (default);
      * ``manual`` — always use *proxy* (``--proxy``); no silent fallback, so a failure is
                     a failure and the operator decides;
      * ``system`` — always use the system proxy (``--proxy-from-system``);
      * ``direct`` — never use a proxy (``--no-proxy`` / tests).
    """
    suffixes = tuple(s for s in (
        [x.strip() for x in no_proxy.split(",")] if isinstance(no_proxy, str) else list(no_proxy)
    ) if s)
    mode = (mode or "auto").lower()
    if mode not in ("auto", "manual", "system", "direct"):
        raise ValueError(f"unknown egress mode: {mode}")
    if mode == "direct":
        return Egress(mode="direct", no_proxy=suffixes, source="flag")

    if mode == "manual":
        if not proxy.strip():
            raise ValueError("--proxy 需要一个代理地址")
        return Egress(mode="manual", proxy=parse_proxy(proxy), source="flag",
                      no_proxy=suffixes)

    url, source, pac = system_proxy()
    if not url:
        # Nothing configured: `system` and `auto` both degrade to direct, and say why.
        return Egress(mode="direct" if mode == "system" else "auto", no_proxy=suffixes,
                      source=source or "none", pac_ignored=pac)
    try:
        parsed = parse_proxy(url)
    except ValueError:
        return Egress(mode="direct", no_proxy=suffixes, source=f"{source}:invalid",
                      pac_ignored=pac)
    if mode == "system":
        return Egress(mode="system", proxy=parsed, source=source, no_proxy=suffixes,
                      pac_ignored=pac)
    return Egress(mode="auto", fallback=parsed, source=source, no_proxy=suffixes,
                  pac_ignored=pac)


# --------------------------------------------------------------------------- sockets
def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("socks: connection closed during handshake")
        buf += chunk
    return buf


def socks5_tunnel(proxy: Proxy, target_host: str, target_port: int,
                  timeout: float) -> socket.socket:
    """Minimal SOCKS5 CONNECT. Implemented here so no extra dependency is required."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        auth = proxy.auth
        sock.sendall(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
        ver, method = _recv_exact(sock, 2)
        if ver != 5:
            raise OSError("socks: bad greeting version")
        if method == 2:
            if not auth:
                raise OSError("socks: proxy demands credentials")
            user, password = auth
            sock.sendall(b"\x01" + bytes([len(user)]) + user.encode()
                         + bytes([len(password)]) + password.encode())
            _, status = _recv_exact(sock, 2)
            if status != 0:
                raise OSError("socks: authentication rejected")
        elif method != 0:
            raise OSError(f"socks: no acceptable auth method ({method})")
        name = target_host.encode("idna") if not target_host.replace(".", "").isdigit() \
            else target_host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                     + struct.pack("!H", int(target_port)))
        ver, reply, _rsv, atyp = _recv_exact(sock, 4)
        if ver != 5 or reply != 0:
            raise OSError(f"socks: connect rejected (code {reply})")
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        elif atyp == 4:
            _recv_exact(sock, 16)
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def http_tunnel(proxy: Proxy, host: str, port: int, timeout: float) -> socket.socket:
    """Open a raw CONNECT tunnel. Used where we need the TLS socket itself (cert probe)."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        head = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        for name, value in proxy.basic_header().items():
            head += f"{name}: {value}\r\n"
        sock.sendall((head + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("proxy closed during CONNECT")
            buf += chunk
            if len(buf) > 65536:
                raise OSError("proxy CONNECT reply too large")
        status = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in status:
            raise OSError(f"proxy CONNECT refused: {status[:80]}")
        return sock
    except Exception:
        sock.close()
        raise


def tls_wrap(sock: socket.socket, host: str, context: ssl.SSLContext) -> socket.socket:
    return context.wrap_socket(sock, server_hostname=host)


def describe_proxy(proxy: Proxy) -> str:
    """Redacted, one-line form for logs (never includes the credential)."""
    return redact_url(f"{proxy.scheme}://{proxy.describe()}")
