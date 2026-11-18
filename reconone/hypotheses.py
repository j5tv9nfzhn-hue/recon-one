"""Hypothesis engine: turn assets and findings into ranked, testable next actions.

This is the layer no surveyed tool has. Each hypothesis states what it assumes, what it would
prove, what it costs and whether it is blocked on access we do not have.
"""
from __future__ import annotations

from .util import clip


def _h(hid, title, statement, requires, verify, success, cost, gain, blocked, origin, tags):
    # gain and cost were the same 1-5 scale but got different weights, so a 2-minute read of a
    # leaked source map tied with a 5-step BOLA matrix. Blocked here now means "you cannot start
    # this today", which must dominate: handoff.md lists it separately.
    score = gain * 3 - min(cost, 5) - (0 if not blocked else 4)
    return {
        "id": hid, "title": title, "statement": statement,
        "requires": requires, "verify": verify, "success_signal": success,
        "cost_minutes": cost, "information_gain": gain, "blocked": blocked,
        "priority_score": score, "origin": origin, "tags": tags,
        "status": "unverified",
    }


def build(hypotheses_input: dict) -> list[dict]:
    """Input carries the already-computed probe results; output is ordered by priority."""
    out: list[dict] = []
    endpoints = hypotheses_input.get("endpoints", [])
    findings = hypotheses_input.get("findings", [])
    secrets = hypotheses_input.get("secrets", [])
    specs = hypotheses_input.get("specs", [])
    graphql = hypotheses_input.get("graphql", [])
    sourcemaps = hypotheses_input.get("sourcemaps", [])
    hosts = hypotheses_input.get("hosts", [])
    forms = hypotheses_input.get("forms", [])
    robots = hypotheses_input.get("robots", [])
    hints = hypotheses_input.get("hints", [])
    n = 0

    def add(*args, **kwargs):
        nonlocal n
        n += 1
        out.append(_h(f"H-{n:03d}", *args, **kwargs))

    for spec in specs:
        add("按 OpenAPI 规范逐端点做对象级授权（BOLA）",
            f"{spec['url']} 暴露 {spec['endpoint_count']} 个端点，spec 中的参数与安全要求可直接映射为测试矩阵。",
            ["两个不同权限的有效身份（普通用户 A / 用户 B）"],
            ["枚举 spec 中含 {id}/{param} 的端点，用 A 的凭据读取 B 的对象",
             "对比响应体字段而非仅状态码"],
            "A 的凭据返回 B 的对象数据（状态 200 且内容不同）",
            4, 5, True, [f"spec:{spec['url']}"], ["authz", "api"])
    for gql in graphql:
        add("GraphQL introspection 开放 → schema 驱动的权限边界枚举",
            f"{gql['url']} 返回完整 schema（{gql['type_count']} 个对象类型），查询面已知，无需猜测。",
            ["一个有效会话（多数业务 schema 的 query 需登录）"],
            ["导出全部 query/mutation", "对每个 mutation 用低权限身份重放",
             "检查嵌套对象是否绕过父级权限"],
            "低权限身份成功执行高权限 mutation，或读到越权节点",
            3, 5, True, [f"graphql:{gql['url']}"], ["authz", "graphql"])
    for cors in findings:
        if cors.get("category") != "cors" or cors.get("severity") not in ("high", "medium"):
            continue
        add("跨源带凭据读取：CORS 反射 + Allow-Credentials",
            f"{cors['evidence'][0]['snippet'][:120] if cors.get('evidence') else ''}",
            ["一个受害者的活跃会话（钓鱼页或浏览器侧触发）"],
            ["构造带 Origin 的页面读取同一接口", "验证 ACAO 反射且 ACAO 与 ACAC 同时生效"],
            "浏览器侧跨源请求成功读取带凭据的响应体",
            6, 4, True, [f"finding:{cors['id']}"], ["cors", "client-side"])
    for secret in secrets:
        add(f"前端硬编码凭据可用性验证（{secret['type']}）",
            f"{secret['masked']} 出现在 {secret['evidence']['file']}，长度 {secret['length']}，为公开资产中的明文。",
            ["该凭据所属平台的账号归属确认（授权范围）"],
            ["用只读 API 验证凭据有效性（如 access key → list-buckets）", "记录权限边界后立即停止"],
            "凭据有效且具备读权限",
            2, 4, False, [f"secret:{secret['type']}"], ["credential"])
    for host in hosts:
        if host.get("kind") != "internal":
            continue
        add("前端引用的内网/内部主机暴露面",
            f"{host['url']} 出现在 {host['source']}，属于内部命名空间。",
            ["能解析或到达该主机的网络位置（VPN/内网立足点）"],
            ["从外网侧确认是否可解析/可达", "若可达，抓取指纹与认证方式"],
            "该主机可从当前网络位置访问",
            3, 3, True, [f"host:{host['url']}"], ["infra", "exposure"])
    dynamic = [e for e in endpoints if "{id}" in e["path"] or "{param}" in e["path"]]
    if dynamic:
        add("动态路径段端点的对象级授权（IDOR）",
            f"{len(dynamic)} 个端点含可变路径段，示例：{', '.join(e['path'] for e in dynamic[:3])}。",
            ["至少一个有效会话"],
            ["取当前身份可访问的对象 ID", "替换为相邻/其他租户 ID", "对比字段级差异"],
            "返回他人对象或错误信息泄露存在性",
            3, 4, True, ["endpoints:dynamic"], ["authz", "idor"])
    admin_paths = [e for e in endpoints
                   if any(k in e["path"].lower() for k in ("admin", "internal", "manage", "debug", "actuator"))]
    if admin_paths:
        add("未授权访问管理/内部路径",
            f"{len(admin_paths)} 个管理类路径暴露在 JSON/JS 中：{', '.join(e['path'] for e in admin_paths[:3])}。",
            ["无（匿名请求即可验证）"],
            ["匿名 GET/POST 各候选路径", "观察 401/403 与 200 的边界", "记录是否有 CSRF/RBAC 前置"],
            "匿名请求返回 200 且包含业务数据或管理界面",
            1, 4, False, ["endpoints:admin"], ["authz", "exposure"])
    for sm in sourcemaps:
        if not sm.get("leaks_original_source"):
            continue
        add("source map 泄露原始源码 → 黑盒转白盒审计",
            f"{sm['url']} 含 sourcesContent（{sm.get('source_count', 0)} 个源文件），可直接恢复前端源码。",
            ["无（资产已可下载）"],
            ["还原 sourcesContent 到本地目录", "对源码做路由/权限/接口的静态审计", "定位隐藏路由与灰度开关"],
            "恢复出可读的业务源码与内部路由",
            2, 4, False, [f"sourcemap:{sm['url']}"], ["source", "whitebox"])
    protected_forms = [f for f in forms if "password" in str(f.get("inputs", "")).lower()]
    if protected_forms:
        add("登录表单的认证边界",
            f"发现 {len(protected_forms)} 个含密码字段的表单，认证入口明确。",
            ["授权内的测试账号"],
            ["检查锁定/限速/验证码", "对比错误信息差异（用户名枚举）", "检查会话固定与登出失效"],
            "存在无速率限制的暴力破解或用户枚举",
            8, 3, True, ["forms:auth"], ["auth"])
    # robots.txt is a wish-list, not a finding. Wildcard/parameterised entries (/pricing/?ref=,
    # /*?from=) are CMS boilerplate; expanding them into one hypothesis each buries the real
    # work under a dozen 1-minute clones. Keep concrete paths, drop the parameterised ones,
    # and fold the rest into a single bounded check.
    concrete = []
    templated = 0
    for path in robots:
        if not path or path in ("/", ""):
            continue
        if "*" in path or "?" in path or "=" in path:
            templated += 1
        else:
            concrete.append(path)
    if concrete:
        listing = "、".join(concrete[:6]) + ("…" if len(concrete) > 6 else "")
        add(f"robots.txt 声明的受限路径可访问性（{len(concrete)} 条）",
            f"robots.txt Disallow 列出的具体路径：{listing}。维护者认为其敏感，值得一次批量探测。",
            ["无（匿名请求即可验证）"],
            ["批量请求这些路径及其变体（大小写/尾斜杠/编码），记录 200 与非 200"],
            f"{len(concrete)} 条路径中出现 200 响应或目录列表",
            1, 2, False, ["robots:concrete"], ["exposure"])
    if templated:
        add("robots.txt 含通配/参数化规则（信息泄露较弱）",
            f"另有 {templated} 条 Disallow 使用 * ? = 通配，多为 CMS 模板生成，通常不指向真实敏感路径。",
            ["无"], ["抽查其中带参数的规则是否可枚举"],
            "存在可枚举的参数化路径", 2, 1, False, ["robots:templated"], ["exposure"])
    for hint in hints:
        if hint["kind"] == "token_in_storage":
            add("令牌存于 Web Storage → XSS 后的会话接管路径",
                f"{hint['file']} 中检测到 token 写入 localStorage/sessionStorage。",
                ["一个可执行脚本的注入点（需先确认 XSS）"],
                ["确认是否存在 XSS 或 DOM 注入 sink", "评估 CSP 是否阻断了利用"],
                "存在可利用的注入点且 CSP 未阻断",
                5, 3, True, ["hint:token_in_storage"], ["client-side", "xss"])
        if hint["kind"] == "basic_auth_in_url":
            add("URL 内嵌基础认证凭据",
                f"{hint['snippet'][:80]}",
                ["无"],
                ["确认凭据所属服务", "验证是否仍有效（只读一次）"],
                "凭据有效",
                1, 3, False, ["hint:basic_auth_in_url"], ["credential"])

    out.sort(key=lambda h: (-h["priority_score"], h["cost_minutes"], h["id"]))
    for index, item in enumerate(out, 1):
        item["rank"] = index
    return out
