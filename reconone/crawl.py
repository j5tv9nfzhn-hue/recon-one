"""Bounded same-origin crawler: pages, links, forms and script references."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from .util import dedupe, in_scope

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".rar", ".pdf", ".css",
            ".exe", ".dmg", ".iso", ".bin")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict] = []
        self.metas: list[dict] = []
        self.title = ""
        self.comments: list[str] = []
        self._in_title = False
        self._in_script = False
        self._buf: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "iframe" and a.get("src"):
            self.links.append(a["src"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
                self._buf = []
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.metas.append({"name": a.get("name", "") or a.get("property", ""),
                               "content": a.get("content", "")})
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text")})
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "inputs": [], "enctype": a.get("enctype", "")}
            self.forms.append(self._form)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._buf).strip()
            if text:
                self.inline_scripts.append(text)
            self._buf = []
        elif tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)
        elif self._in_title:
            self.title += data.strip()

    def handle_comment(self, comment):
        if len(self.comments) < 40:
            self.comments.append(comment.strip()[:300])


def normalize(base: str, href: str) -> str:
    if not href:
        return ""
    href = href.strip()
    if href.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return ""
    try:
        absolute = urljoin(base, href)
    except ValueError:
        return ""
    p = urlsplit(absolute)
    if p.scheme not in ("http", "https"):
        return ""
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def crawl(session, start_url: str, max_pages: int = 40, max_depth: int = 2,
          domain: str | None = None) -> dict:
    queue: list[tuple[str, int]] = [(start_url, 0)]
    seen: set[str] = set()
    pages: list[dict] = []
    scripts: list[str] = []
    forms: list[dict] = []
    links: list[str] = []

    while queue and len(pages) < max_pages and not session.exhausted:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = session.request(url, headers={"Accept": "text/html,application/xhtml+xml"})
        if resp.error or resp.status >= 400:
            continue
        ctype = resp.header("content-type", "").lower()
        if ctype and "html" not in ctype and "xml" not in ctype:
            continue
        parser = PageParser()
        try:
            parser.feed(resp.text())
        except Exception:
            continue
        page_scripts = [normalize(url, s) for s in parser.scripts]
        page_scripts = [s for s in dedupe(page_scripts) if s]
        scripts.extend(page_scripts)
        for form in parser.forms:
            form["page"] = url
            form["action"] = normalize(url, form.get("action") or url)
            forms.append(form)
        outgoing = []
        for href in parser.links:
            target = normalize(url, href)
            if not target:
                continue
            links.append(target)
            host = (urlsplit(target).hostname or "")
            if domain and not in_scope(host, domain):
                continue
            if target.split("?")[0].lower().endswith(SKIP_EXT):
                continue
            outgoing.append(target)
        pages.append({
            "url": url, "status": resp.status, "title": parser.title[:200],
            "depth": depth, "bytes": len(resp.body),
            "scripts": sorted(set(page_scripts)),
            "inline_scripts": [s[:20000] for s in parser.inline_scripts],
            "forms": parser.forms,
            "meta": parser.metas[:30],
            "comments": parser.comments,
        })
        if depth < max_depth:
            for target in dedupe(outgoing):
                if target not in seen:
                    queue.append((target, depth + 1))

    return {
        "pages": pages,
        "scripts": sorted(set(s for s in scripts if s)),
        "forms": forms,
        "links": sorted(set(links)),
        "seen": len(seen),
    }
