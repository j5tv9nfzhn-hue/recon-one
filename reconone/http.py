"""Scope-guarded HTTP client with byte/time budgets, manual redirects and evidence logging."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
import zlib
from urllib.parse import urlsplit, urlunsplit, urljoin

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
                 budget_seconds: float | None = None):
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

    def _once(self, url: str, method: str, data: bytes | None,
              headers: dict | None, max_bytes: int | None) -> Response:
        parts = urlsplit(url)
        scheme = (parts.scheme or "https").lower()
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
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
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self._ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.request(method, target, body=data, headers=hdrs)
            raw = conn.getresponse()
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
            elapsed = int((time.time() - started) * 1000)
            self.requests += 1
            self.bytes_total += len(body)
            if self.bytes_total >= self.max_total_bytes:
                self.exhausted = True
            self.log.append({"url": url, "status": raw.status, "bytes": len(body),
                             "ms": elapsed, "method": method})
            return Response(url, raw.status, resp_headers, body, elapsed, truncated=truncated,
                            header_list=header_list)
        except ssl.SSLError as exc:
            self.requests += 1
            return self._fail(url, "tls", str(exc))
        except socket.timeout:
            self.requests += 1
            return self._fail(url, "timeout", f"no response within {self.timeout}s")
        except socket.gaierror as exc:
            self.requests += 1
            return self._fail(url, "dns", str(exc))
        except (ConnectionError, OSError) as exc:
            self.requests += 1
            return self._fail(url, "connect", str(exc))
        except http.client.HTTPException as exc:
            self.requests += 1
            return self._fail(url, "http", repr(exc))
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


def probe_tls_certificate(host: str, port: int = 443, timeout: float = 8.0, verify: bool = True) -> dict:
    """Separate handshake because http.client does not expose the peer certificate."""
    import hashlib
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    out: dict = {"host": host, "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
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
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        out["error"] = f"tls: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return out
