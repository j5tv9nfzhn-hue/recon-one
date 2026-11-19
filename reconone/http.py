"""Scope-guarded HTTP client with byte/time budgets, manual redirects and evidence logging."""
from __future__ import annotations

import errno
import http.client
import socket
import ssl
import time
import zlib
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import cookiejar as cookiejarmod
from . import egress as egressmod
from . import inject as injectmod
from . import rate as ratemod
from .config import DEFAULT_UA
from .util import in_scope



def _inflate(data: bytes, encoding: str, cap: int) -> tuple[bytes, bool]:
    """Decompress `data` with a hard output cap. Returns (body, hit_cap).

    `gzip.decompress`/`zlib.decompress` expand a whole stream in one go, so a few hundred
    kilobytes of well-crafted input can produce gigabytes and defeat the byte budget that
    was checked before the request. Streaming with `max_length` keeps memory bounded; the
    stream is left unfinished on purpose when the cap is hit.
    """
    wbits = 16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
    for candidate in (wbits, -zlib.MAX_WBITS):
        try:
            engine = zlib.decompressobj(candidate)
            out = engine.decompress(data, cap)
            return out, bool(engine.unconsumed_tail)
        except zlib.error:
            continue
    return data, False          # not actually compressed: keep the raw bytes

class Response:
    __slots__ = ("url", "status", "headers", "body", "elapsed_ms", "error", "redirect_chain",
                 "truncated", "header_list")

    def __init__(self, url, status=0, headers=None, body=b"", elapsed_ms=0,
                 error=None, redirect_chain=None, truncated=False, header_list=None):
        self.url = url
        self.status = status
        self.headers = headers or {}
        # Raw (name, value) pairs in wire order. The dict above keeps the last value of a
        # repeated header, which silently dropped every Set-Cookie but one.
        self.header_list = list(header_list) if header_list else []
        self.body = body
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.redirect_chain = redirect_chain or []
        self.truncated = truncated

    def header_values(self, name: str) -> list[str]:
        """Every value of a repeated header, in wire order (falls back to the dict view)."""
        want = (name or "").lower()
        values = [v for k, v in self.header_list if k.lower() == want]
        if values:
            return values
        single = self.headers.get(want)
        return [single] if single else []

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def text(self) -> str:
        ctype = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    def json(self):
        import json as _json
        try:
            return _json.loads(self.text())
        except (ValueError, UnicodeDecodeError):
            return None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class Session:
    """Every request passes a scope check; every failure is classified, never swallowed."""

    def __init__(self, domain: str, timeout: float = 12.0, max_total_bytes: int = 40_000_000,
                 allow_external: bool = False, max_body: int = 4_000_000,
                 verify_tls: bool = True, user_agent: str = DEFAULT_UA,
                 budget_seconds: float | None = None, egress=None,
                 injection=None, limiter=None, cookies=None):
        self.domain = domain.lower()
        self.timeout = timeout
        self.max_total_bytes = max_total_bytes
        self.max_body = max_body
        self.allow_external = allow_external
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.bytes_total = 0
        # 并发下"已派发但还没落地"的字节必须预占，否则 N 条连接会一起通过
        # 派发前的预算检查，然后各自下载完毕 —— 40MB 上限会被突破 N 倍。
        self.reserved_bytes = 0
        self.requests = 0
        self.log: list[dict] = []
        self.errors: list[dict] = []
        self.exhausted = False
        self.deadline = (time.time() + budget_seconds) if budget_seconds else None
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self.off_scope_attempts: list[str] = []
        # Egress is a property of the *run*, not of the target: `Egress()` means direct,
        # which keeps every existing caller (and test) on today's behaviour.
        self.egress = egress if egress is not None else egressmod.Egress()
        self.fallback_count = 0
        # Session credentials and per-host pacing. Both default to "off", so existing callers
        # keep today's behaviour byte for byte.
        self.injection = injection if injection is not None else injectmod.Injection()
        self.limiter = limiter if limiter is not None else ratemod.Limiter()
        # Set-Cookie persistence. A caller that does not pass a jar gets a disabled one, so
        # `Session(domain)` keeps behaving exactly like a scanner with no cookie support.
        self.cookies = cookies if cookies is not None else cookiejarmod.CookieJar(enabled=False)

    # -- scope -----------------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:          # malformed URL (e.g. unbalanced brackets) is never in scope
            return False
        if not host:
            return False
        if in_scope(host, self.domain):
            return True
        return self.allow_external

    def budget_left(self) -> bool:
        if self.exhausted:
            return False
        if self.deadline and time.time() > self.deadline:
            self.exhausted = True
            return False
        if self.bytes_total >= self.max_total_bytes:
            self.exhausted = True
            return False
        return True

    def _fail(self, url: str, kind: str, detail: str) -> Response:
        entry = {"url": url, "kind": kind, "detail": detail[:300]}
        self.errors.append(entry)
        return Response(url, error=f"{kind}: {detail}"[:300])

    # -- request ---------------------------------------------------------------
    def request(self, url: str, method: str = "GET", data: bytes | None = None,
                headers: dict | None = None, max_bytes: int | None = None,
                follow: bool = True, max_redirects: int = 5) -> Response:
        chain: list[str] = []
        current = url
        for _ in range(max_redirects + 1):
            if not self.in_scope(current):
                self.off_scope_attempts.append(current)
                return Response(current, error="out_of_scope: blocked by policy", redirect_chain=chain)
            if not self.budget_left():
                return Response(current, error="budget_exhausted: byte or time cap reached",
                                redirect_chain=chain)
            resp = self._once(current, method, data, headers, max_bytes)
            if resp.error is not None:
                resp.redirect_chain = chain
                return resp
            chain = chain + [current] if chain else [current]
            loc = resp.header("location")
            if follow and resp.status in (301, 302, 303, 307, 308) and loc:
                nxt = urljoin(current, loc)
                if resp.status == 303:
                    method, data = "GET", None
                current = nxt
                continue
            resp.redirect_chain = chain
            return resp
        return self._fail(url, "redirect_limit", f"more than {max_redirects} redirects")

    # -- transport -------------------------------------------------------------
    @staticmethod
    def _kind(exc: BaseException) -> str:
        """Classify one transport failure; the kind drives both the report and the retry."""
        if isinstance(exc, socket.gaierror):
            return "dns"
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return "connect-timeout"
        if isinstance(exc, ssl.SSLError):
            return "tls"
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return "reset"
        if isinstance(exc, ConnectionRefusedError):
            return "refused"
        if isinstance(exc, http.client.HTTPException):
            return "http"
        code = getattr(exc, "errno", None)
        if code == errno.ECONNREFUSED:
            return "refused"
        if code == errno.ECONNRESET:
            return "reset"
        if code == errno.ETIMEDOUT:
            return "connect-timeout"
        return "connect"

    def _open(self, scheme: str, host: str, port: int, proxy, path_query: str):
        """Return (connection, request_target, extra_headers) for one attempt.

        Three routes, each with its own wire format:
        * direct — origin-form request to the host;
        * HTTP proxy — `CONNECT` tunnel for https, absolute-URI for http (RFC 7230 §5.3.2);
        * SOCKS5 — CONNECT handshake, then TLS wraps the tunnel for https.
        """
        if proxy is None:
            if scheme == "https":
                return (http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                                    context=self._ctx), path_query, {})
            return http.client.HTTPConnection(host, port, timeout=self.timeout), path_query, {}
        if proxy.is_socks:
            raw = egressmod.socks5_tunnel(proxy, host, port, self.timeout)
            if scheme == "https":
                sock = egressmod.tls_wrap(raw, host, self._ctx)
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                                   context=self._ctx)
            else:
                sock = raw
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.sock = sock            # pre-connected: http.client must not dial again
            return conn, path_query, {}
        if scheme == "https":
            conn = http.client.HTTPSConnection(proxy.host, proxy.port, timeout=self.timeout,
                                               context=self._ctx)
            conn.set_tunnel(host, port, headers=proxy.basic_header() or None)
            return conn, path_query, {}
        absolute = f"{scheme}://{host}" + ("" if port == 80 else f":{port}")
        return (http.client.HTTPConnection(proxy.host, proxy.port, timeout=self.timeout),
                absolute + path_query, proxy.basic_header())

    def _cookie_header(self, host: str, path: str, secure: bool, hdrs: dict) -> str:
        """Merge the injected cookie with the jar's, injected names winning.

        An operator who passed `--cookie "sid=..."` is asserting an identity; a `Set-Cookie`
        for the same name must not silently replace it mid-scan, or the report would mix two
        identities without saying so. Everything else is additive.
        """
        injected = ""
        for name, value in hdrs.items():
            if name.lower() == "cookie":
                injected = str(value or "")
                break
        from_jar = self.cookies.header_for(host, path, secure)
        if not from_jar:
            return injected
        if not injected:
            return from_jar
        taken = {part.split("=", 1)[0].strip().lower()
                 for part in injected.split(";") if "=" in part}
        extra = [part.strip() for part in from_jar.split(";")
                 if part.split("=", 1)[0].strip().lower() not in taken]
        return "; ".join([injected] + extra) if extra else injected

    def _attempt(self, url: str, method: str, data: bytes | None, headers: dict | None,
                 max_bytes: int | None, proxy) -> Response:
        parts = urlsplit(url)
        scheme = (parts.scheme or "https").lower()
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        path_query = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        started = time.time()
        conn = None
        waited = self.limiter.before(host, deadline=self.deadline)
        try:
            conn, target, extra = self._open(scheme, host, port, proxy, path_query)
            if extra:
                hdrs.update(extra)
            hdrs = self.injection.apply(hdrs)
            # One `Cookie` header, assembled once: injected pairs (the operator's identity) and
            # the jar (what the site handed us). Anything the caller passed in is dropped so a
            # duplicate header can never be sent.
            cookie_header = self._cookie_header(host, parts.path or "/", scheme == "https", hdrs)
            hdrs = {name: value for name, value in hdrs.items() if name.lower() != "cookie"}
            if cookie_header:
                hdrs["Cookie"] = cookie_header
            conn.request(method, target, body=data, headers=hdrs)
            raw = conn.getresponse()
            self.limiter.after(host, raw.status,
                               {str(k).lower(): v for k, v in raw.getheaders()})
            if proxy is not None and raw.status in (502, 503, 504):
                # A proxy answering 5xx means the *proxy* could not reach the target. Treating
                # that as a page would make "unreachable" look "scannable": the run would be
                # scored against a proxy error page and every downstream stage would lie.
                raw.read(2048)
                self.requests += 1
                self.log.append({"url": url, "status": raw.status, "bytes": 0, "ms": 0,
                                 "method": method, "egress": "proxy", "error": "proxy-error"})
                return self._fail(url, "proxy-error", f"proxy returned {raw.status}")
            cap = max_bytes or self.max_body
            body = raw.read(cap)
            truncated = len(body) >= cap
            enc = (raw.getheader("Content-Encoding") or "").strip().lower()
            if enc in ("gzip", "deflate"):
                # Cap the *output*, not just the input: a 4 MB body can inflate to
                # gigabytes and blow straight through max_total_bytes (zip bomb).
                body, hit_cap = _inflate(body, enc, cap)
                truncated = truncated or hit_cap
            # Keep the wire order: dict(headers) keeps only the last of repeated headers,
            # which silently dropped every Set-Cookie but one.
            header_list = list(raw.getheaders())
            resp_headers = {k.lower(): v for k, v in header_list}
            # Absorb `Set-Cookie` before the response leaves this function: the next page in
            # the crawl is already authenticated, which is the whole point of the jar.
            self.cookies.store(host, parts.path or "/", scheme == "https",
                               [value for name, value in header_list
                                if name.lower() == "set-cookie"])
            elapsed = int((time.time() - started) * 1000)
            self.requests += 1
            self.bytes_total += len(body)
            if self.bytes_total >= self.max_total_bytes:
                self.exhausted = True
            self.log.append({"url": url, "status": raw.status, "bytes": len(body),
                             "ms": elapsed, "method": method, "wait_ms": int(waited * 1000),
                             "egress": "proxy" if proxy else "direct"})
            return Response(url, raw.status, resp_headers, body, elapsed, truncated=truncated,
                            header_list=header_list)
        except Exception as exc:                      # noqa: BLE001 - classified, never lost
            self.requests += 1
            return self._fail(url, self._kind(exc), f"{type(exc).__name__}: {exc}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _once(self, url: str, method: str, data: bytes | None,
              headers: dict | None, max_bytes: int | None) -> Response:
        """One request on the primary route, with at most one fallback retry.

        The retry exists for exactly one failure shape: the direct path could not open a
        connection (timeout / reset / refused) and a system proxy is available. It never
        retries a TLS error or an HTTP status — those are answers from *something*, and
        replaying them through another route would only produce a second wrong answer.
        """
        host = (urlsplit(url).hostname or "").lower()
        primary = self.egress.route_for(host)
        resp = self._attempt(url, method, data, headers, max_bytes, primary)
        if resp.error is None:
            return resp
        kind = resp.error.split(":", 1)[0]
        fallback = self.egress.fallback_for(host)
        if fallback is None or kind not in ("connect-timeout", "reset", "refused"):
            return resp
        self.fallback_count += 1
        self.log.append({"url": url, "status": 0, "bytes": 0, "ms": 0, "method": method,
                         "egress": "fallback", "first_error": kind})
        retry = self._attempt(url, method, data, headers, max_bytes, fallback)
        if retry.error is not None:
            # Both routes failed. Keep the direct failure as the answer and record that the
            # fallback was tried; "two ways failed" must not read like "the target answered".
            resp.error = f"{resp.error} · fallback: {retry.error.split(':', 1)[0]}"[:300]
            return resp
        return retry


def egress_view(session) -> dict:
    """What went out and how, for `meta.egress` (never includes proxy credentials)."""
    egress = getattr(session, "egress", None)
    if egress is None:                    # sessions built before egress existed
        return {"mode": "direct", "type": "direct", "host": "", "source": "unknown",
                "fallback": False, "fallback_used": 0, "fallback_requests_pct": 0.0,
                "no_proxy": [], "pac": {"detected": False, "supported": False}}
    return egress.view(fallback_count=getattr(session, "fallback_count", 0),
                       requests=getattr(session, "requests", 0))

def probe_tls_certificate(host: str, port: int = 443, timeout: float = 8.0, verify: bool = True,
                          egress=None) -> dict:
    """Read the peer certificate — through the run's egress, never as a hidden direct dial.

    `http.client` never exposes the certificate, so this has to open its own TLS socket. It
    still has to *leave the machine the same way as everything else*: direct, through an HTTP
    CONNECT tunnel, or through a SOCKS5 tunnel. Otherwise the one field that proves where the
    target actually lives would be collected over a different route than the report claims.
    """
    import hashlib
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    proxy = egress.route_for(host) if egress is not None else None
    out: dict = {"host": host, "port": port,
                 "egress": ("proxy" if proxy is not None else "direct")}
    sock = None
    try:
        if proxy is None:
            sock = socket.create_connection((host, port), timeout=timeout)
        elif proxy.is_socks:
            sock = egressmod.socks5_tunnel(proxy, host, port, timeout)
        else:
            sock = egressmod.http_tunnel(proxy, host, port, timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            der = tls.getpeercert(binary_form=True) or b""
            out["subject"] = {k: v for item in cert.get("subject", []) for k, v in item}
            out["issuer"] = {k: v for item in cert.get("issuer", []) for k, v in item}
            out["san"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            out["not_before"] = cert.get("notBefore", "")
            out["not_after"] = cert.get("notAfter", "")
            out["serial"] = cert.get("serialNumber", "")
            out["tls_version"] = tls.version()
            out["cipher"] = (tls.cipher() or ("", "", 0))[0]
            out["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
            out["der_bytes"] = len(der)
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"tls_verify: {exc.verify_message or exc}"
        out["error_kind"] = "tls"
    except Exception as exc:                        # noqa: BLE001 - classified, never lost
        out["error"] = f"{Session._kind(exc)}: {exc}"[:200]
        out["error_kind"] = Session._kind(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return out
