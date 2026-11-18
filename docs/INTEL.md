# 情报与目标画像（评估两个核心问题）

本文回答两件事，并说明代码里的落点：

1. **怎么在不下载前端、不逆向 bundle 的前提下拿到接口面**（`--no-js`）。
2. **这个目标值不值得打、有多难、机会窗口多大**（`report.profile`）。

全流程**不依赖 AI**：没有任何模型调用、没有嵌入、没有"让 LLM 判断"。所有结论都是规则表 +
可核查的观测值，同一份 report 重算得到同一份结论。

---

## 0. 调研结论（2026-11，实际联网核对）

| 来源 | 实测到的事实 | 对本项目的取舍 |
|---|---|---|
| **crt.sh** | 证书搜索，JSON 形态为 `?q=%.<domain>&output=json`；写入本文时多次返回 `502 Bad Gateway` | 作为**回退**源保留：主源用 CertSpotter，crt.sh 失败不影响能力可用性 |
| **CertSpotter** | `api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&expand=dns_names`，返回 `dns_names / not_before / not_after / revoked` | 作为**主源**：字段稳定、无 key 限制内可直接用 |
| **web-check**（Lissy93，3.5 万 star） | 其 `src/client/jobs/registry.ts` 列出 40 个 job：`get-ip, location, ssl, whois, quality, tech-stack, shodan, cookies, trackers, headers, dns, http-security, mixed-content, tls-connection, tls-labs, subdomains, trace-route, security-txt, dns-server, firewall, dnssec, caa-records, hsts, threats, breaches, mail-config, archives, rank, redirects, linked-pages, robots-txt, status, ports, txt-records, block-lists, sitemap, screenshot, social-tags, social-presence, carbon` | 取它**不依赖第三方 key**的那一半：子域、DNS/加密封装、archive、robots/sitemap/linked-pages、location、tech-stack。**不取**需要付费 key 的（shodan / tls-labs / rank / breaches / threats） |
| **Wayback CDX** | `web.archive.org/cdx/search/cdx?url=<domain>&matchType=domain&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey` | 作为"历史存档"与"被动接口发现"的数据源；实测会超时，因此**必须**能降级为 `unavailable` |

web-check 的做法是"一个站点一屏 40 张卡片"，本项目不复制它的 UI，只复制它的问题清单；
把答案压成三个可判定的数字（价值 / 难度 / 机会窗口），并保留每条结论的驱动项。

---

## 1. 两条路径：被动 vs 主动

这是本项目最重要的一条边界。每个检查项都带 `mode`，报告里可以直接筛。

| | 被动（`passive`） | 主动（`active`） |
|---|---|---|
| 谁收到了我们的请求 | 第三方索引 / 注册局 / 解析器 | **目标服务器本身** |
| 具体动作 | 查 CT 日志、查 Wayback CDX、查 GeoIP、查 NVD、读 `rules/*.json` | 抓首页、爬同源页面、下 bundle、探测 spec/GraphQL 路径、CORS 反射、路径枚举 |
| 目标能否看见你 | 不能（DNS 解析除外，那是解析器看见你） | 能（UA、来源 IP、请求路径全部可见） |
| 开关 | `--no-intel` 关掉全部；`--geo` / `--cve` 单独开 | `--no-js` / `--no-graphql` / `--no-dns` 分项关 |
| 报告字段 | `profile.mode_split.passive` | `profile.mode_split.active` |

`--no-js` 是**被动优先**的组合：不下载任何 bundle，接口面只来自链接、表单、robots、
sitemap 与历史存档。对应测试见 `tests/test_pipeline.py::TestNoJsMode`（断言 `raw/js/` 为空）。

---

## 2. 维度 → 数据源 → 落点

| 维度 | 数据源 | 被动/主动 | 代码 | 报告字段 |
|---|---|---|---|---|
| 深度 DNS | 自实现 DNS（A/AAAA/CNAME/MX/NS/TXT/SOA + SPF/DMARC） | 主动（对解析器） | `dns.py` | `assets.dns`、`profile.dimensions.dns` |
| 子域 | Certificate Transparency（CertSpotter → crt.sh） | 被动 | `intel.ct_subdomains` | `intel.ct`、`profile.dimensions.subdomains` |
| 历史存档 | Wayback CDX（快照数、首末时间、历史路径） | 被动 | `intel.wayback` | `intel.archive`、`profile.dimensions.history` |
| 历史路径里的敏感面 | 上者的路径列表 + 关键词表 | 被动 | `intel._ARCHIVE_SENSITIVE` | `worth.archive_sensitive` |
| 接口枚举 | 链接 / 表单 / robots / sitemap / 存档 / OpenAPI / GraphQL | 混合（逐条带 `sources`） | `jsanalyze.from_paths`、`apiprobe` | `endpoints[].sources` |
| 指纹与网站类型 | `rules/technologies.json` + 关键词规则表 | 主动（读响应）/ 本地规则 | `webprobe.fingerprint`、`intel.classify_site` | `assets.technology`、`profile.dimensions.site_type` |
| 服务器信息 | 响应头 `server` / `x-powered-by` / TLS 版本 / WAF 特征头 | 主动 | `webprobe.analyze_headers`、`triage._hardness_checks` | `profile.dimensions.infra` |
| 地理位置 | ip-api.com（需 `--geo`） | 被动 | `intel.geoip` | `profile.dimensions.geo` |
| 历史漏洞线索 | NVD 2.0 keywordSearch（需 `--cve`，仅对有版本号的 product） | 被动 | `intel.cve_hints` | `profile.dimensions.cve_hints` |
| 价值 / 难度 / 机会窗口 | 以上全部，经规则表加权 | 派生 | `triage.build` | `profile.axes`、`profile.success` |

**为什么地理位置与 CVE 默认关闭**：两者都会把目标信息交给第三方（ip-api、NIST），且 NVD 无 key
时严格限流。默认关闭 + 显式开关，比"偷偷发出去"更符合这个工具"数据不出站"的既有承诺。

---

## 3. 三个数字怎么算

### 3.1 价值 `worth`（0–100，越高越值得测）

| 检查项 | 权重 | 判定依据 |
|---|---:|---|
| `worth.write_endpoints` | 18 | POST/PUT/PATCH/DELETE 端点数：≥10 pass，3–9 warn |
| `worth.subdomains` | 14 | CT 子域数：≥8 pass，2–7 warn；未取得 → unknown |
| `worth.api_spec` | 12 | 公开 OpenAPI/Swagger |
| `worth.graphql` | 10 | introspection 开放 |
| `worth.parameters` | 10 | 具名参数（查询串/请求体/规范）≥8 pass |
| `worth.api_surface` | 10 | 端点落在 `/api/`、`/v1`、`/rest`、`/graphql` 下 |
| `worth.archive_sensitive` | 10 | 历史路径里的敏感词（admin/api/internal/debug…） |
| `worth.disclosure` | 8 | 有 `security.txt`（有交付出口） |
| `worth.auth_surface` | 8 | 存在含密码字段的表单（有认证边界可测） |

### 3.2 难度 `hardness`（0–100，越高越难）

| 检查项 | 权重 | 判定依据 |
|---|---:|---|
| `hard.waf` | 16 | 命中 CDN/WAF 特征头或 `server`（cloudflare/akamai/imperva/fastly…） |
| `hard.hygiene` | 14 | 复用 `score.axes.hygiene`：≥70 难，50–70 中 |
| `hard.stack_age` | 12 | 技术栈命中 PHP/jQuery/WordPress/IIS… |
| `hard.tls` | 10 | TLS1.2/1.3 为“难”，更老为“易” |
| `hard.version_hidden` | 10 | 响应头是否暴露版本号 |
| `hard.subdomain_sprawl` | 10 | 子域越多面越大、越难一次摸清 |
| `hard.rate_limit` | 8 | **永远 unknown**：静态探测看不见限流 |
| `hard.mfa` | 10 | **永远 unknown**：没有账号就看不见 MFA |

后两项刻意标成 unknown：它们对"是否容易打"影响极大，但**观测不到**。硬编码一个猜测值，
正是本项目一直在避免的那类失真。

### 3.3 机会窗口 `success`（不是概率）

```
ease   = 100 - hardness
index  = clamp(0.55 * worth + 0.45 * ease, 5, 95)      # 仅当 min(coverage) ≥ 60%
band   : ≥70 high / ≥50 elevated / ≥30 moderate / 其余 low
```

* 输出字段 `success.is_probability = false`，`range` 只是档位区间，不是置信区间。
* 覆盖率 < 60% 时 `index = null`、`band = unknown`，并列出 `coverage.unknown`。
* 四条假设写在 `profile.assumptions` 里随报告一起交付，避免读者把它当漏洞概率。

---

## 4. 运行方式

```powershell
# 主动 + 被动（默认）：抓首页、爬同源、下 bundle、探 spec/GraphQL
python -m reconone scan --domain example.com

# 不下载任何前端 bundle：接口面来自链接/表单/robots/sitemap/历史存档
python -m reconone scan --domain example.com --no-js

# 纯被动：连目标的一个包都不发（DNS 仍需解析，故配合 --no-dns 才完全不触碰）
python -m reconone scan --domain example.com --no-js --no-dns --out runs\example.com-passive

# 需要地理位置 / CVE 线索时显式开启（会把目标信息发给第三方）
python -m reconone scan --domain example.com --geo --cve

# 完全不要第三方：只要目标自身的数据
python -m reconone scan --domain example.com --no-intel
```

Web 控制台同样可选：扫描页第二排的 `下载前端 bundle`（默认勾选）/ `被动情报（CT / 存档）` /
`地理位置` / `CVE 线索`，四个开关原样透传给 `cli.run_scan`，控制台不做任何二次推断。

---

## 5. 失败与未知的处理（可核查）

| 情形 | 报告里长什么样 |
|---|---|
| crt.sh 502、certspotter 超时 | `intel.ct.status = unavailable`，`worth.subdomains = unknown`（不是 fail） |
| Wayback 超时 | `intel.archive.status = unavailable`，`worth.archive_sensitive = unknown` |
| 目标不可达 | 仍会跑被动情报（CT/存档按域名查，不需要目标在线），`web = unreachable` |
| IP 目标 | 自动跳过 CT/存档（它们只索引域名），`status = skipped` 并写明原因 |
| 未开 `--geo` / `--cve` | `status = disabled` + 原因，不计分、不视为通过 |

---

## 6. 已知边界（写在报告里，不藏在文档里）

1. `worth`/`hardness` 只覆盖**未认证时可观测的外围**；业务逻辑、租户隔离、容器边界不在其中。
2. 机会窗口是**线性合成的经验指数**，不是漏洞存在概率，也不预测单次尝试结果。
3. CVE 查询是**关键词语义匹配**：命中不等于可利用，未命中不等于安全（版本号可能被后端改写）。
4. 子域只有 CT 记录里出现过的那些；私有 CA 签发或从未签发的内网域名不会出现。
5. Wayback 的 `sensitive_paths` 是"历史上存在过的路径"，今天可能已经 404 —— 它只是线索。

---

## 7. 非 JS 端点的来源与置信度

`--no-js` 时端点全部来自下面五条来源，逐条带 `sources`，合并规则是「按归一化路径合并，
取最高置信度，`sources` / `params` 取并集」（`jsanalyze.merge_endpoints`）：

| 来源 `source` | 输入 | 置信度 | 说明 |
|---|---|---:|---|
| `html-link` | 爬取到的 `<a href>` | medium | 人眼可见的导航路径 |
| `html-form` | `<form action>` | medium | 表单即写端点候选，配套 `params` 来自 input 名 |
| `robots` | `robots.txt` 的 `Disallow` / `Allow` | low | 常常直接暴露后台与调试路径 |
| `sitemap` | `sitemap.xml` 的 `<loc>` | low | 页面清单，不等于接口 |
| `wayback` | CDX 返回的历史 URL | low | 历史上存在过，今天可能 404 |

置信度只影响排序与展示，不影响是否入表：低置信度的 `robots` / `wayback` 往往正是最有价值的那一行，
所以它们被标为 low 而不是被丢掉。

---

## 8. 同一份结论的四个落点

画像只算一次（`report.assemble()` 内 `triage.build`），四处展示的都是它的投影，因此数字永远一致：

| 落点 | 位置 | 用途 |
|---|---|---|
| 机器事实源 | `report.json` → `profile` | 下游程序/AI 直接读；含 `checks[]` 逐项证据 |
| 人读版 | `report.md` → 「目标画像」表 | 一眼看三个数字与各维度状态（未观测就写状态与原因） |
| 简报 | `brief.md` → 第 1 节「目标画像」 | 消费方第一屏就知道值不值得投入 |
| 控制台 | 概览视图顶部卡片 | 同上，数值直接取 `profile`，缺失时显示「未生成」而不是 0 |

`deterministic_digest` 只取画像的**稳定投影**（排除 `fetched_at`、`reason` 与自由文本），
所以「同一目标两次扫描摘要相同」这条不变式不因引入情报而失效。

---

## 9. 主动探测如何进入评分（轻量边界）

主动探测不是「扫得更狠」，而是**把已经发出的请求变成可计分的证据**。本轮新增两项检查，
并把权重口径写进每一份报告（`profile.weights`）：

| 检查 | 轴 | 权重 | 判定 | 数据来源 |
|---|---|---:|---|---|
| `worth.live_surface` | 价值 | 8 | 本次运行里由抓取/爬取直接得到的端点（`js-call`/`js-config`/`openapi-spec`/`html-form`/`html-link`）≥8 pass、≥2 warn | `endpoints[].sources` + `coverage.probes` |
| `hard.active_blocking` | 难度 | 6 | 已发出的请求中，返回 401/403/405/406/429/503 的比例 ≥20% pass、有拦截 warn | `meta.probe_stats`（来自 `session.log`） |

权重现在是：价值 10 项合计 **108**，难度 9 项合计 **96**；主动项（170）合计占比 **83.3%**，
被动项（34）占 16.7%。报告同时给出两个更有用的比例：

* `weights.active_share_pct` —— 权重表里主动项的占比（设计口径）。
* `weights.observed_share_pct` —— **本次实际计分的权重**里来自主动实测的比例。它比前者重要：
  一次 `--no-intel` 的运行里它接近 100%，只有在被动情报也成功时才回落到真实比例。

**为什么不会滑向渗透**：`worth.live_surface` 只数本次已经拿到的端点，`hard.active_blocking`
只对已发出的请求做比例统计——两者都不新增任何请求。新增请求需要改 `config.PROFILES` 的预算，
而预算里没有目录爆破、参数模糊测试或载荷注入的位置。这条边界写在 `profile.assumptions` 里，
随报告一起交付，不靠口头承诺。

---

## 10. 子域与存档：从「有个数字」到「能落地用」

上一版的子域只到 `intel.ct.subdomains` 与一个计数。现在它进入报告的资产层：

```json
"assets": {"subdomains": [{"host": "a.example.com", "url": "https://a.example.com/",
                           "source": "crt.sh", "passive": true, "probed": false,
                           "first_cert": "...", "last_cert": "..."}]}
```

三个诚实标签缺一不可：`passive: true`（数据来自第三方索引）、`probed: false`（本次**没有**
扫描它）、`source`（哪个日志给的）。控制台、`report.md`、`brief.md` 读同一份列表，
所以不会出现「页面显示 3 个子域、报告说 2 个」这种漂移。

Wayback 也一样：它的路径既进入 `endpoints[].sources = ["wayback"]`（可测），也进入
`profile.dimensions.surface.historic_paths`（作为面规模证据）。

### 可用性加固（为什么它们不再是占位）

| 加固点 | 具体做法 | 原因 |
|---|---|---|
| 单次失败重试 | `intel._retry()`：每个 provider 最多尝试 2 次，间隔 0.8s | crt.sh 实测成片 502、Wayback 会先卡后通，一次重试就能把「坏的一分钟」变成数据 |
| 分 provider 超时 | CT / Geo 12s、Wayback **25s**、NVD 15s | 归档索引比 JSON API 慢一个数量级，用同一个超时等于必然超时 |
| 主备切换 | CertSpotter 主 → crt.sh 备，两家失败原因都写进 `reason` | 任一家的可用性都不该决定能力是否可用 |
| 失败即 `unavailable` | 不改写成「没有」；对应检查落 `unknown` | 第三方挂了 ≠ 目标干净 |

可核查：`tests/test_intel.py::TestRetry` 断言「第一次失败、第二次成功 → 最终 ok」与
「彻底不通 → 恰好尝试 2 次后 unavailable」；`TestSubdomainsBecomeAssets` 断言 CT 主机落地成
`probed: false` 的资产，且 CT 失败时列表为空而不是伪造条目。

---

## 11. 依赖自检：`python -m reconone doctor`

`import httpx` 成功不代表能跑：残缺的 wheel、缺 `ssl` 绑定的解释器、被裁掉并发原语的环境都能
通过 import，然后在第一次请求时以「目标不可达」的样子失败——这是最贵的一种误判。

```
  [ok  ] deps.python  Python 运行时 — python 3.13.17
  [ok  ] deps.httpx   httpx 客户端可构造 — httpx 0.28.1 client ok
  [ok  ] deps.anyio   anyio TaskGroup + 限流器 — anyio 4.16.0 taskgroup+limiter ok
  [ok  ] deps.dns     DNS UDP 套接字 — dns udp socket ok (ipv4+ipv6)
  [ok  ] deps.ssl     TLS 默认上下文（校验证书） — OpenSSL 3.5.9 verify=required
[doctor] 5/5 通过 · python 3.13.17 · httpx 0.28.1 · anyio 4.16.0
```

* 五项都是**行为**检查：构造 client、跑一个 4 任务的 TaskGroup + `CapacityLimiter(2)`、
  开 UDP 套接字、建默认 TLS 上下文并确认 `CERT_REQUIRED`。
* 不联网、不写盘、不调用模型；失败时保留异常文本与头几层栈，退出码 `4`（与缺依赖一致）。
* 每份报告带 `meta.deps`（python / httpx / anyio / ssl 版本），「这份结论产生在什么运行时」
  可以事后核对——但 `meta.deps` 与 `meta.probe_stats` 都**不进入** `deterministic_digest`：
  它们描述这次运行，不描述目标。
