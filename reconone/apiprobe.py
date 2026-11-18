"""API surface discovery: OpenAPI/Swagger specs, GraphQL introspection, parameter aggregation."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from .concurrency import probe_many
from .util import clip, norm_endpoint

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json",
    "/api/v1/openapi.json", "/docs/openapi.json", "/openapi.yaml", "/swagger.yaml",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
INTROSPECTION = {
    "query": "{__schema{queryType{name} mutationType{name} subscriptionType{name} "
             "types{name kind fields{name}}}}"
}


def _spec_shape(data) -> str:
    if not isinstance(data, dict):
        return ""
    if str(data.get("openapi", "")).startswith("3"):
        return "openapi3"
    if str(data.get("swagger", "")).startswith("2"):
        return "swagger2"
    if "paths" in data and isinstance(data.get("paths"), dict):
        return "paths-only"
    return ""


def _parse_spec(data: dict, spec_url: str) -> dict:
    kind = _spec_shape(data)
    paths = data.get("paths") or {}
    endpoints = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = [p.get("name") for p in (op.get("parameters") or []) if isinstance(p, dict)]
            body = op.get("requestBody") or {}
            if isinstance(body, dict):
                schema = ((body.get("content") or {}).get("application/json") or {}).get("schema") or {}
                params += list((schema.get("properties") or {}).keys())
            endpoints.append({
                "path": norm_endpoint(path), "raw": path, "methods": [method.upper()],
                "params": [p for p in params if p],
                "requires_auth": bool(op.get("security") or data.get("security")),
                "summary": clip(op.get("summary") or op.get("description") or "", 120),
                "confidence": "high", "sources": ["openapi-spec"],
                "evidence": [{"file": spec_url, "offset": 0, "snippet": clip(f"{method.upper()} {path}", 120)}],
            })
    security = []
    for name, scheme in ((data.get("components") or {}).get("securitySchemes") or {}).items():
        security.append({"name": name, "type": scheme.get("type", ""),
                         "scheme": scheme.get("scheme", ""), "in": scheme.get("in", ""),
                         "bearer_format": scheme.get("bearerFormat", "")})
    return {
        "kind": kind, "title": clip(str(data.get("info", {}).get("title", "")), 120),
        "version": str(data.get("info", {}).get("version", "")),
        "servers": data.get("servers") or ([{"url": data.get("host", "")}] if data.get("host") else []),
        "security_schemes": security,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }


def discover_specs(session, base_url: str) -> dict:
    found, tried = [], []
    # 12 个候选路径彼此无依赖，全是纯等待 —— 串行跑等于把 12 个超时叠起来。
    # 并发后的 tried 顺序与 SPEC_PATHS 一致（probe_many 保证同序），报告不会抖。
    pairs = probe_many(session, base_url, SPEC_PATHS, max_bytes=4_000_000)
    for url, resp in pairs:
        tried.append({"url": url, "status": resp.status, "error": resp.error})
        if resp.error or resp.status >= 400:
            continue
        text = resp.text().strip()
        if not text.startswith("{"):
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not _spec_shape(data):
            continue
        parsed = _parse_spec(data, url)
        parsed["url"] = url
        found.append(parsed)
        break
    return {"found": found, "tried": tried}


def probe_graphql(session, base_url: str, candidates: list[str]) -> dict:
    paths = sorted(set(GRAPHQL_PATHS) | set(candidates or []))
    result = []
    body = json.dumps(INTROSPECTION).encode()
    pairs = probe_many(session, base_url, paths, method="POST", data=body,
                       headers={"Content-Type": "application/json"},
                       max_bytes=2_000_000, limit=8)
    for url, resp in pairs:
        if resp.error:
            continue
        data = resp.json()
        if not isinstance(data, dict) or "errors" in data and "data" not in data:
            continue
        schema = (data.get("data") or {}).get("__schema")
        if not schema:
            continue
        types = schema.get("types") or []
        objects = [t for t in types if isinstance(t, dict) and t.get("kind") == "OBJECT"
                   and not str(t.get("name", "")).startswith("__")]
        result.append({
            "url": url,
            "introspection_enabled": True,
            "query_type": (schema.get("queryType") or {}).get("name", ""),
            "mutation_type": (schema.get("mutationType") or {}).get("name", ""),
            "type_count": len(objects),
            "types": [{"name": t.get("name"), "fields": len(t.get("fields") or [])} for t in objects[:60]],
        })
    return {"endpoints": result, "tried": paths[:8]}


def discover(session, base_url: str, js_result: dict) -> dict:
    specs = discover_specs(session, base_url)
    graphql = probe_graphql(session, base_url, js_result.get("graphql", []))
    params: dict[str, dict] = {}
    for item in js_result.get("params", []):
        params[item["name"]] = {"name": item["name"], "in": item.get("in", "query"),
                                "endpoints": item["endpoints"], "source": item.get("source", "")}
    for spec in specs["found"]:
        for endpoint in spec["endpoints"]:
            for name in endpoint["params"]:
                entry = params.setdefault(name, {"name": name, "in": "spec", "endpoints": [],
                                                 "source": spec["url"]})
                if endpoint["path"] not in entry["endpoints"]:
                    entry["endpoints"].append(endpoint["path"])
    return {
        "specs": specs["found"],
        "spec_probes": specs["tried"],
        "graphql": graphql,
        "parameters": sorted(params.values(), key=lambda p: p["name"]),
    }
