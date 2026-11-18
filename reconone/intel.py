"""Passive intelligence: certificate transparency, web archives, geo, CVE hints.

Design contract
---------------
* **Nothing here touches the target.** Every provider either reads a third-party index
  (Certificate Transparency logs, Wayback Machine) or a public registry (IP geolocation,
  NVD). That is why the whole module is labelled `passive` and can be switched off with
  `--no-intel`: an operator who does not want the target's name leaving to a third party
  keeps it off, and the report says `disabled` instead of inventing a value.
* **No observation, no claim.** Each call returns `status` one of
  `ok / empty / disabled / unavailable`, with `reason` when it is not `ok`. Callers must
  treat anything but `ok` as `unknown`, never as "nothing found".
* **No AI.** Every value is a literal field from a JSON document, normalised and sorted.
  The only inference is `classify_site()`, which is a keyword/rule table you can read.

Provider inventory (what each dimension actually comes from):

| dimension        | provider                     | source of truth                    |
|------------------|------------------------------|------------------------------------|
| subdomains       | CertSpotter, then crt.sh     | Certificate Transparency logs      |
| historical URLs  | Wayback CDX                  | Internet Archive snapshots         |
| ip / location    | ip-api.com                   | public GeoIP (opt-in)              |
| cve hints        | NVD 2.0 keyword search       | NIST NVD (opt-in)                  |
| site type        | local rule table             | fingerprints + title + paths       |
"""
from __future__ import annotations

import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

PASSIVE = "passive"
ACTIVE = "active"

UA = "recon-one/1.0 (authorized assessment; passive intel)"
TIMEOUT = 12.0
MAX_BYTES = 4_000_000

OK, EMPTY, DISABLED, UNAVAILABLE = "ok", "empty", "disabled", "unavailable"

_WILDCARD = re.compile(r"^\*\.")
_HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


# --------------------------------------------------------------------------- transport
def fetch_json(url: str, timeout: float = TIMEOUT) -> object:
    """Single GET → JSON. Injected in tests, so this is the only network entry point."""
    req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as res:          # noqa: S310 - fixed https origins
        raw = res.read(MAX_BYTES)
    return json.loads(raw.decode("utf-8", "replace"))


def _result(status: str, source: str, reason: str = "", **payload) -> dict:
    out = {"status": status, "source": source, "passive": True,
           "reason": reason or "", "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                              time.gmtime())}
    out.update(payload)
    return out


def _call(fn, *args, **kwargs):
    """Run one provider, folding every failure into `unavailable` + reason."""
    try:
        return fn(*args, **kwargs)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return _result(UNAVAILABLE, "network", reason=f"{type(exc).__name__}: {exc}"[:200])


WAYBACK_TIMEOUT = 25.0        # the CDX index stalls far longer than a plain JSON API
RETRY_ATTEMPTS = 2
RETRY_DELAY = 0.8


def _fetch_with_timeout(fetch, url: str, timeout: float):
    """Call the fetcher, passing a timeout only to the real transport.

    Tests inject one-argument fakes; `fetch_json` takes a timeout, and the archive needs a
    much larger one than a JSON API. Branching here keeps that fact out of every provider.
    """
    if fetch is fetch_json:
        return fetch(url, timeout=timeout)
    return fetch(url)


def _retry(fetch, url: str, *, timeout: float = TIMEOUT,
           attempts: int = RETRY_ATTEMPTS, delay: float = RETRY_DELAY):
    """One GET with a bounded retry.

    The failure mode of these indexes is transient - crt.sh answers 502 in bursts and
    Wayback stalls and then answers - so one retry turns a bad minute into data. It cannot
    turn a real absence into data: when nothing is there the status stays `empty`.
    """
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return _fetch_with_timeout(fetch, url, timeout)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            last = exc
            if attempt < attempts and delay > 0:
                time.sleep(delay)
    raise last if last is not None else RuntimeError("retry without an exception")


# --------------------------------------------------------------------------- subdomains

def _norm_host(value: str, domain: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    host = _WILDCARD.sub("", host)
    if not host or not _HOST_OK.match(host):
        return ""
    if host == domain or host.endswith("." + domain):
        return host
    return ""


def ct_subdomains(domain: str, fetch=fetch_json) -> dict:
    """Certificate Transparency: every host that ever appeared in a certificate.

    CertSpotter is queried first because crt.sh routinely answers `502 Bad Gateway`
    (verified while writing this module); crt.sh stays as the fallback so the capability
    does not depend on one operator.
    """
    domain = (domain or "").lower().strip(".")
    if not domain:
        return _result(UNAVAILABLE, "ct", reason="empty domain")

    url = ("https://api.certspotter.com/v1/issuances?domain=" + quote(domain) +
           "&include_subdomains=true&expand=dns_names")
    try:
        rows = _retry(fetch, url)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        rows = None
        primary_error = f"{type(exc).__name__}: {exc}"[:160]
    else:
        primary_error = ""

    source = "certspotter"
    certs = []
    if isinstance(rows, list):
        for item in rows:
            if not isinstance(item, dict):
                continue
            names = [n for n in (_norm_host(v, domain) for v in item.get("dns_names") or []) if n]
            certs.append({"names": sorted(set(names)),
                          "not_before": item.get("not_before", ""),
                          "not_after": item.get("not_after", ""),
                          "revoked": bool(item.get("revoked"))})
    else:
        # crt.sh fallback: ?q=%.domain&output=json
        try:
            rows = _retry(fetch, "https://crt.sh/?q=" + quote("%." + domain) + "&output=json")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return _result(UNAVAILABLE, "ct",
                           reason=f"certspotter: {primary_error or 'bad payload'}; "
                                  f"crt.sh: {type(exc).__name__}: {exc}"[:240])
        source = "crt.sh"
        if isinstance(rows, list):
            for item in rows:
                if not isinstance(item, dict):
                    continue
                names = [n for n in (_norm_host(v, domain)
                                     for v in str(item.get("name_value") or "").splitlines()) if n]
                certs.append({"names": sorted(set(names)),
                              "not_before": item.get("not_before", ""),
                              "not_after": item.get("not_after", ""),
                              "revoked": False})

    hosts: set[str] = set()
    for cert in certs:
        hosts.update(cert["names"])
    hosts.discard(domain)
    stamps = sorted(c["not_before"] for c in certs if c.get("not_before"))
    if not hosts:
        return _result(EMPTY, source, reason="no certificate names for this domain",
                       subdomains=[], certs=len(certs),
                       first_cert=stamps[0] if stamps else "",
                       last_cert=stamps[-1] if stamps else "")
    return _result(OK, source, subdomains=sorted(hosts), certs=len(certs),
                   first_cert=stamps[0] if stamps else "",
                   last_cert=stamps[-1] if stamps else "")


# --------------------------------------------------------------------------- archives
_ARCHIVE_SENSITIVE = ("admin", "api", "internal", "portal", "manage", "debug",
                      "staging", "test", "dev", "backup", "upload", "login", "sso")


def wayback(domain: str, fetch=fetch_json, limit: int = 400) -> dict:
    """Internet Archive CDX: how much history exists and which paths it remembers.

    The URL list is the *passive* alternative to downloading bundles: an endpoint that was
    linked in 2019 shows up here without a single byte of JavaScript being fetched.
    """
    domain = (domain or "").lower().strip(".")
    if not domain:
        return _result(UNAVAILABLE, "wayback", reason="empty domain")
    url = ("https://web.archive.org/cdx/search/cdx?url=" + quote(domain) +
           "&matchType=domain&output=json&fl=timestamp,original,statuscode,mimetype"
           "&collapse=urlkey&limit=" + str(int(limit)))
    try:
        rows = _retry(fetch, url, timeout=WAYBACK_TIMEOUT)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return _result(UNAVAILABLE, "wayback", reason=f"{type(exc).__name__}: {exc}"[:200])

    if not isinstance(rows, list) or len(rows) <= 1:
        return _result(EMPTY, "wayback", reason="no snapshots", snapshots=0, urls=[])

    header = [str(h).lower() for h in rows[0]]
    try:
        i_ts, i_url = header.index("timestamp"), header.index("original")
    except ValueError:
        return _result(UNAVAILABLE, "wayback", reason=f"unexpected cdx columns: {header}")
    i_status = header.index("statuscode") if "statuscode" in header else -1
    i_mime = header.index("mimetype") if "mimetype" in header else -1

    urls: list[dict] = []
    hosts: set[str] = set()
    for row in rows[1:]:
        if not isinstance(row, list) or len(row) <= i_url:
            continue
        original = str(row[i_url])
        parts = urlsplit(original if "://" in original else "http://" + original.lstrip("/"))
        host = (parts.hostname or "").lower()
        if host and (host == domain or host.endswith("." + domain)):
            hosts.add(host)
        urls.append({
            "url": original,
            "path": parts.path or "/",
            "query": parts.query,
            "timestamp": str(row[i_ts]),
            "status": row[i_status] if 0 <= i_status < len(row) else "",
            "mimetype": row[i_mime] if 0 <= i_mime < len(row) else "",
        })

    stamps = sorted(u["timestamp"] for u in urls if u["timestamp"])
    paths = sorted({u["path"] for u in urls})
    sensitive = sorted({p for p in paths
                        if any(word in p.lower() for word in _ARCHIVE_SENSITIVE)})
    return _result(OK, "wayback", snapshots=len(urls), first=stamps[0] if stamps else "",
                   last=stamps[-1] if stamps else "", hosts=sorted(hosts)[:200],
                   paths=paths[:300], sensitive_paths=sensitive[:100], urls=urls[:300])


# --------------------------------------------------------------------------- geo
def geoip(ip: str, fetch=fetch_json, enabled: bool = False) -> dict:
    """Public GeoIP for one address. Opt-in: it tells a third party what you look at."""
    if not enabled:
        return _result(DISABLED, "ip-api", reason="geo lookup disabled (--geo to enable)")
    ip = (ip or "").strip()
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return _result(UNAVAILABLE, "ip-api", reason=f"not an address: {ip[:40]}")
    url = ("http://ip-api.com/json/" + quote(ip) +
           "?fields=status,message,country,regionName,city,isp,org,as,query")
    try:
        data = _retry(fetch, url, timeout=8.0)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return _result(UNAVAILABLE, "ip-api", reason=f"{type(exc).__name__}: {exc}"[:200])
    if not isinstance(data, dict) or data.get("status") != "success":
        return _result(UNAVAILABLE, "ip-api",
                       reason=str((data or {}).get("message", "bad payload"))[:160])
    return _result(OK, "ip-api", ip=data.get("query", ip), country=data.get("country", ""),
                   region=data.get("regionName", ""), city=data.get("city", ""),
                   isp=data.get("isp", ""), org=data.get("org", ""), asn=data.get("as", ""))


# --------------------------------------------------------------------------- cve hints
def cve_hints(products: list[str], fetch=fetch_json, enabled: bool = False,
              per_product: int = 5, max_products: int = 2) -> dict:
    """Keyword lookup against NVD for the versions the target already advertises.

    This is *not* a vulnerability scanner: it answers "have these exact product/version
    strings ever been assigned a CVE", so a reader can follow the link. Absence of a hit
    proves nothing, and the report says so.
    """
    if not enabled:
        return _result(DISABLED, "nvd", reason="cve lookup disabled (--cve to enable)")
    wanted = [p.strip() for p in (products or []) if p.strip()][:max_products]
    if not wanted:
        return _result(EMPTY, "nvd", reason="no versioned product in headers",
                       hits=[], checked=[])
    hits, checked = [], []
    for product in wanted:
        checked.append(product)
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
               quote(product) + "&resultsPerPage=" + str(int(per_product)))
        try:
            data = _retry(fetch, url, timeout=15.0)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return _result(UNAVAILABLE, "nvd", reason=f"{type(exc).__name__}: {exc}"[:200],
                           hits=hits, checked=checked)
        if not isinstance(data, dict):
            continue
        for item in data.get("vulnerabilities") or []:
            cve = ((item or {}).get("cve") or {})
            metrics = (cve.get("metrics") or {})
            score = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []
                if entries:
                    score = str(((entries[0] or {}).get("cvssData") or {}).get("baseScore", ""))
                    break
            hits.append({"id": cve.get("id", ""), "product": product, "score": score,
                         "summary": (cve.get("descriptions") or [{}])[0].get("value", "")[:200]})
    status = OK if hits else EMPTY
    return _result(status, "nvd", reason="" if hits else "no CVE matched these strings",
                   hits=hits[:20], checked=checked)


# --------------------------------------------------------------------------- site type
# Deterministic rule table. Each hit is one point for the category; the report keeps the
# evidence strings so a reader can disagree with the label.
SITE_RULES: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    ("ecommerce", ("shop", "cart", "checkout", "product", "order", "sku", "price"),
     ("shopify", "magento", "woocommerce", "bigcommerce", "prestashop")),
    ("saas-app", ("dashboard", "workspace", "subscription", "billing", "tenant", "pricing"),
     ("react", "vue", "angular", "next.js", "nuxt", "svelte")),
    ("admin-console", ("admin", "manage", "console", "backoffice", "operator"),
     ("grafana", "jenkins", "kibana", "adminer", "phpmyadmin")),
    ("api-first", ("/api/", "openapi", "swagger", "graphql", "rest"),
     ("express", "fastapi", "django", "spring", "laravel")),
    ("cms-blog", ("post", "article", "category", "tag", "archive"),
     ("wordpress", "ghost", "drupal", "joomla", "hugo", "jekyll")),
    ("docs-site", ("docs", "guide", "reference", "changelog"),
     ("docusaurus", "gitbook", "mkdocs", "readthedocs")),
    ("forum", ("thread", "topic", "forum", "reply"),
     ("discourse", "phpbb", "vbulletin", "flarum")),
    ("static-marketing", ("landing", "about", "contact", "careers"),
     ("netlify", "vercel", "github-pages", "cloudflare-pages")),
]


def classify_site(tech: list[dict] | None = None, title: str = "",
                  paths: list[str] | None = None, headers: dict | None = None) -> dict:
    """Score the site against a readable keyword table; no model, no inference chain."""
    tech_names = " ".join(str(t.get("name", "")).lower() for t in (tech or []))
    title_low = (title or "").lower()
    path_blob = " ".join(str(p).lower() for p in (paths or []))
    header_blob = " ".join(f"{k} {v}" for k, v in (headers or {}).items()).lower()
    scored = []
    for category, path_words, tech_words in SITE_RULES:
        score, evidence = 0, []
        for word in tech_words:
            if word in tech_names:
                score += 2
                evidence.append(f"tech:{word}")
        for word in path_words:
            if word in title_low:
                score += 1
                evidence.append(f"title:{word}")
            if word in path_blob:
                score += 2
                evidence.append(f"path:{word}")
            if word in header_blob:
                score += 1
                evidence.append(f"header:{word}")
        if score:
            scored.append({"type": category, "score": score, "evidence": sorted(set(evidence))})
    scored.sort(key=lambda x: (-x["score"], x["type"]))
    return {"status": OK if scored else EMPTY,
            "primary": scored[0]["type"] if scored else "unknown",
            "candidates": scored[:4],
            "passive": True, "source": "local rules"}


def gather(domain: str, *, fetch=fetch_json, geo_enabled: bool = False,
           cve_enabled: bool = False, ip: str = "", products: list[str] | None = None,
           limit: int = 400) -> dict:
    """All passive dimensions in one call. Never raises; each key carries its own status."""
    ct = _call(ct_subdomains, domain, fetch)
    archive = _call(wayback, domain, fetch, limit)
    geo = (_call(geoip, ip, fetch, geo_enabled) if ip
           else _result(DISABLED, "ip-api", reason="no IP resolved"))
    cves = _call(cve_hints, products or [], fetch, cve_enabled)
    return {"passive": True, "domain": domain, "ct": ct, "archive": archive,
            "geo": geo, "cve": cves,
            "providers": {"ct": ct.get("source", ""), "archive": archive.get("source", ""),
                          "geo": geo.get("source", ""), "cve": cves.get("source", "")}}
