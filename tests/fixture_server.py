"""A deliberately vulnerable fixture site: exercises every probe without touching a real host."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_HOLDER = {"port": 0}

MINIFIED = (
    'var apiBase="/api/v1";'
    'function loadUser(id){return fetch("/api/v1/users/"+id,{method:"GET"})}'
    'function login(u){return axios.post("/api/v1/login",u)}'
    'function graph(){return fetch("/graphql",{method:"POST"})}'
    'var cfg={baseURL:"/api/v1",debug:true};'
    'var _region="AKIAIOSFODNN7EXAMPLE";'
    'var internal="http://internal-admin.corp.local/api/debug";'
    'localStorage.setItem("auth_token", window.token);'
    'var __pad="' + "a" * 6000 + '";'
)

SOURCEMAP = {
    "version": 3,
    "file": "app.min.js",
    "sources": ["webpack:///src/pages/admin/Dashboard.vue", "webpack:///src/api/client.js"],
    "sourcesContent": ["export default { name: 'Dashboard' }", "export const client = {}"],
}

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Fixture API", "version": "1.0.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/api/v1/users/{id}": {
            "get": {"summary": "read user", "security": [{"bearer": []}],
                    "parameters": [{"name": "id", "in": "path"}]}
        },
        "/api/v1/admin/export": {
            "post": {"summary": "export all tenants", "security": [{"bearer": []}],
                     "requestBody": {"content": {"application/json": {
                         "schema": {"properties": {"tenantId": {}, "format": {}}}}}}}
        },
    },
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
}

INDEX_HTML = """<!doctype html><html><head><title>Fixture Portal</title>
<meta name="generator" content="Fixture 1.0">
<script src="/static/app.min.js"></script>
<script src="/static/missing.js"></script></head>
<body><a href="/about">About</a><a href="/admin">Admin</a>
<form action="/api/v1/login" method="post">
<input name="username"><input name="password" type="password">
</form>
<script>var inlineCfg={endpoint:"/api/v1/inline/health"};</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):                     # noqa: N802 - the verifier asks with HEAD first
        # `_send()` already suppresses the body for HEAD, so this is the whole implementation.
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?")[0]
        origin = self.headers.get("Origin", "")
        cors = {}
        if origin and path.startswith("/api/"):
            cors = {"Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true"}
        if path == "/":
            return self._send(INDEX_HTML.encode())
        if path == "/about":
            return self._send(b"<html><title>About</title><a href='/'>home</a></html>")
        if path == "/admin":
            return self._send(b"<html><title>Admin</title>tenant dump</html>")
        if path == "/static/app.min.js":
            body = MINIFIED + "\n//# sourceMappingURL=/static/app.min.js.map\n"
            return self._send(body.encode(), ctype="application/javascript")
        if path == "/static/app.min.js.map":
            return self._send(json.dumps(SOURCEMAP).encode(), ctype="application/json")
        if path == "/openapi.json":
            return self._send(json.dumps(OPENAPI).encode(), ctype="application/json")
        if path == "/robots.txt":
            return self._send(b"User-agent: *\nDisallow: /admin\nDisallow: /internal\n", ctype="text/plain")
        if path.startswith("/api/"):
            return self._send(json.dumps({"user": {"id": "1", "email": "a@example.test"}}).encode(),
                              ctype="application/json", extra=cors)
        return self._send(b"not found", status=404, ctype="text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path.split("?")[0] == "/graphql":
            try:
                query = json.loads(raw or b"{}").get("query", "")
            except ValueError:
                query = ""
            if "__schema" in query:
                payload = {"data": {"__schema": {
                    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "me"}]},
                              {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "grantRole"}]},
                              {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "email"}]}]}}}
                return self._send(json.dumps(payload).encode(), ctype="application/json")
            return self._send(b'{"errors":[{"message":"bad query"}]}', ctype="application/json")
        return self._send(b'{"ok":true}', ctype="application/json")


def start(port: int = 0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    PORT_HOLDER["port"] = server.server_address[1]
    return server


def stop(server):
    server.shutdown()
    server.server_close()
