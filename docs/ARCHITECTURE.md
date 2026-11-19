# 项目架构

`recon-one` 是单域名侦察工具：一个域名进，一份带证据与优先级的结构化报告包出。
本文描述代码结构、数据流向与模块职责边界，供改动前的定位使用。

---

## 1. 目录总览

```
recon-one/
  README.md                  项目说明与能力边界
  start-recon-one.pyw        双击启动 Web 控制台（pythonw 会重新拉起带控制台的 python.exe）
  docs/
    ARCHITECTURE.md          本文
    ACCEPTANCE.md            15 条验收标准与逐条对应测试
    RESEARCH.md              同类工具能力边界调研（设计依据）
  reconone/                  唯一源码包，主干只用标准库（并发层可选 httpx+anyio）
  rules/                     数据驱动的规则表（JSON，非代码）
  tests/                     验收测试与内置靶站（test_pipeline / test_concurrency / test_web）
  webui/                     控制台前端：index.html + app.js + app.css（无框架、无构建）
  runs/                      扫描产物（运行时生成）
```

**约束**：`reconone/` 的探测逻辑只依赖 Python 标准库；`httpx` + `anyio` 是全局硬依赖（并发层直接
import，缺失时启动阶段即报错并给出安装命令）。无 Docker、无外部 API key。所有请求直达目标，默认不出站。

---

## 2. 分层与依赖

依赖是单向的，没有循环。`config` 与 `util` 是叶子，`cli` 是唯一编排层。

```
            __main__.py
                 │
                 ▼
   ┌──────────── cli.py  (编排层 / 唯一入口) ────────────┐
   │            │            │           │              │
   ▼            ▼            ▼           ▼              ▼
 dns.py     webprobe.py   crawl.py   jsanalyze.py   apiprobe.py
                 │                        │              │
                 ▼                        │              │
              http.py ◄───────────────────┴──────────────┘
                 │
     ┌───────────┴───────────┐
     ▼                       ▼
 hypotheses.py            report.py
     │                       │
     └───────────┬───────────┘
                 ▼
        config.py   util.py        (叶子：无内部依赖)

  web.py ──► cli.py, config.py      (仅调用编排层，不含探测逻辑)
```

| 模块 | 行数 | 扇入 | 职责 |
|---|---:|---:|---|
| `util.py` | 334 | 8 | 哈希、密钥脱敏、**响应头/URL/证据片段脱敏**、URL 归一化、确定性 JSON、JS 美化、端点归一 |
| `redact.py` | 181 | 1 | 第五层兜底脱敏：按**形状**（Bearer/JWT/`token=`/凭据键名/任意 URL）与**本次发出的凭据值**（`[redacted:sent-credential]`，覆盖目标回显）扫描整份报告，并输出可机读的 `meta.redaction` |
| `egress.py` | 322 | 2 | 出口策略：`--proxy`/系统代理（env + WinINET）/`--direct`/bypass、SOCKS5 握手（自实现，无额外依赖）、`meta.egress` |
| `config.py` | 199 | 8 | 版本号、**授权声明常量**、三档扫描预算、输出根解析、规则加载（带缓存） |
| `http.py` | 442 | 3 | 作用域守卫的 HTTP 客户端：代理四路由（直连/CONNECT/绝对 URI/SOCKS5）、TLS 证书探测同路由、**注入头合并 + cookie 合成 + 逐 host 限速/退避**、失败分类、回退重试、预算与解压上限 |
| `dns.py` | 283 | 1 | 自实现 DNS 线格式（A/AAAA/CNAME/MX/NS/TXT/SOA），校验应答源与 txid，无 dnspython |
| `concurrency.py` | 170 | 1 | 并发抓取（httpx + anyio，硬依赖）：同序返回、共享字节预算 |
| `webprobe.py` | 269 | 1 | 首页抓取、安全头按值评分、Cookie 标志、技术指纹、well-known、CORS 实测 |
| `crawl.py` | 161 | 1 | 同源 BFS，受深度/页数限制，抽取链接、表单、内联脚本、注释 |
| `jsanalyze.py` | 520 | 1 | 前端 JS 静态分析：端点/参数/密钥/主机/source map；`from_paths()` 提供非 JS 来源 |
| `apiprobe.py` | 145 | 1 | OpenAPI/Swagger 发现与解析、GraphQL introspection、参数聚合 |
| `intel.py` | 381 | 1 | 被动情报：唯一对外网络出口（可注入），CT 子域 / Wayback 存档 / geo / CVE 逐项 status；单次重试 + 分 provider 超时，永不抛 |
| `triage.py` | 515 | 2 | 目标画像：10 项价值 + 9 项难度规则表（含两项主动实测）、覆盖率门槛、机会指数（非概率）、passive/active 与权重占比；**下注判决 `bet()`**（阈值 A：匿名可访问且带参数 / 存活子域暴露非公开面，三态） |
| `verify.py` | 309 | 2 | 验证 v2：单身份 `HEAD` 判存在（405/501 补一次 GET）、双身份两次 `GET` 做**授权差分**（anon/authed 状态 + 长度/标题差异 → `gated`/`anonymous_open`/`same`）；RoE 方法/上限 + 作用域守卫双检，破坏性动词按词边界跳过 |
| `inject.py` | 177 | 2 | 会话注入：`--cookie/--bearer/--header` 与 `RECONONE_*` 合成不可变头表；`describe()` 只暴露头名与 Cookie 键名（无键片段只计数），`secrets()` 仅供脱敏层按值遮蔽，值永不进报告 |
| `rate.py` | 120 | 2 | 逐 host 限速与退避：`1/rate` 间隔、429/503 → `Retry-After` 或指数退避（0.5→8s 封顶）、单次等待上限、`stats()` 记账 |
| `cookiejar.py` | 251 | 2 | Set-Cookie 会话保持（RFC 6265 实用子集）：`Domain`/`Path` 作用域、`Secure` 双向校验、`Max-Age`/`Expires`/删除、上限淘汰；**只接受目标或其子域的 Domain**，`stats()` 只给名称与计数 |
| `hypotheses.py` | 165 | 1 | 决策层：把事实转成带前置条件、验证步骤、成本与增益的假设 |
| `score.py` | 782 | 2 | 证据门控评分：18 个原子检查、两轴、覆盖率门槛、triage 规则树 |
| `report.py` | 1007 | 1 | 报告组装、画像注入、**下注判决块**、子域资产、主动遥测、`meta.egress`/`meta.roe`/`meta.session`（含 `cookies`）/`meta.rate`、**请求台账 `requests.jsonl`**、验证块、会话与速率摘要、授权块与五层脱敏（含发出凭据的值级遮蔽）、Schema 校验、markdown/handoff 渲染 |
| `brief.py` | 404 | 1 | AI 简报：授权行 + 画像摘要 + 验证结论 + 会话/速率行 + 按决策价值排序、硬字符预算 |
| `doctor.py` | 148 | 2 | 依赖自检：行为级验证 httpx 客户端、anyio TaskGroup+限流器、DNS 套接字、TLS 校验；不联网 |
| `cli.py` | 615 | 2 | 参数解析（`--authorized-by` / `--proxy` 系列 / `--no-verify` / `--cookie` / `--bearer` / `--header` / `--rate` / `--max-backoff` / `--no-cookies`）、出口解析、会话装配（注入 + jar + **匿名对照 session**）、验证阶段、阶段编排、`doctor`、退出码 |
| `web.py` | 738 | 2 | 控制台后端：静态资源 + JSON API（统一鉴权）、多目标并行批次（出口/验证/会话/速率/`use_cookies` 透传）、产物管理、读时重算评分、`/api/compare` |
| `auth.py` | 228 | 1 | 一次性配对令牌、PBKDF2 密码、30 天持久会话（哈希落盘）与失败限流 |

`web.py` 与 `cli.py` 之间是**单向**依赖：控制台不含任何探测逻辑，所以命令行与浏览器产出**字节一致**的报告。

---

## 3. 数据流

`cli.run_scan()` 是唯一的流水线，每个阶段把结果交给下一个阶段，最后统一进 `report.assemble()`。

```
  domain
    │
    ├─► dns.dns_probe ──────────────────────┐
    │                                       │
    ├─► webprobe.probe_web ─────────────────┤   assets.dns
    │     ├── probe_tls_certificate         │   assets.tls
    │     ├── analyze_headers               │   assets.technology
    │     ├── WELL_KNOWN 探测                │   assets.well_known
    │     └── probe_cors                    │
    │                                       │
    ├─► intel.gather ───────────────────────┤   intel（全部 passive：不向目标发包）
    │     ├── ct_subdomains()  CT 日志子域   │   intel.ct
    │     ├── wayback()        历史存档      │   intel.archive
    │     ├── geoip()          位置（可选）  │   intel.geo
    │     └── cve_hints()      版本 CVE（可选）│  intel.cve
    │                                       │
    ├─► crawl.crawl ────────────────────────┤   assets.pages / forms
    │                                       │
    ├─► jsanalyze.analyze ──────────────────┤   assets.scripts
    │     ├── extract()  ← 端点/参数/密钥    │   endpoints / parameters
    │     ├── _fetch_sourcemap()            │   secrets
    │     └── 全文 _scrub() 脱敏             │
    │                                       │
    ├─► apiprobe.discover ──────────────────┤   specs / graphql
    │     ├── discover_specs()              │
    │     └── probe_graphql()               │
    │                                       │
    ├─► report.derive_findings() ───────────┤   findings
    ├─► hypotheses.build() ─────────────────┤   hypotheses（排序 + rank）
    │                                       │
    └─► report.assemble() ◄─────────────────┘
          │  ├── score.score_report()   18 个原子检查 → 两轴分数 + triage
          │  ├── validate()      JSON Schema 子集校验
          │  ├── deterministic_digest  排除时间戳的稳定摘要
          │  ├── brief.build_brief()   brief.md（必须在 write_all 之前写，否则不进 manifest）
          │  └── write_all()     report.json/md/handoff/schema + 4×jsonl + manifest
          ▼
       runs/<domain>/
```

### 3.1 阶段与退出码

| 阶段 | 探测 | 状态值 |
|---|---|---|
| `dns` | 全部记录类型 + `_dmarc` | `ok` / `partial(n)` / `skipped` / `error` |
| `web` | 首页、TLS、安全头、well-known | `ok` / `unreachable` |
| `intel` | CT 子域、Wayback 存档、geo、CVE（第三方索引，不向目标发包） | `ok` / `skipped` / `unavailable` |
| `crawl` | 同源 BFS | `ok` / `empty` |
| `js` | bundle 下载与静态分析 | `ok` / `no-scripts` |
| `api` | 规范发现 + GraphQL | `ok` / `none-found` |
| `cors` | 反射实测 | `ok` |

> `no-scripts` / `skipped` 时，JS 派生的三项检查（sourcemap、密钥、内部主机）是 `unknown` 而不是
> `fail`：没抓过 bundle 就不能宣称「扫过且没有」。实现见 `score._js_was_observed()`。
>
> 同理，`intel` 里任一项 `unavailable`（例如 Wayback 超时）会让对应检查（`worth.archive_sensitive`）
> 落到 `unknown`：第三方不可用不等于目标没有问题。

退出码：`0` 全部 `ok`；`2` 部分成功（报告仍可用，未覆盖项在 `coverage.probes`）；`3` 目标不可达。

> 注意：`skipped`（主动关闭）与 `none-found`（探了没有）语义不同，但当前都计入「不完整」。

---

## 4. 关键设计点

### 4.1 作用域守卫
所有请求都必须过 `http.Session.in_scope()`。越界请求**不发出**，只记入 `off_scope_attempts`。
`--allow-external` 是唯一放行开关，默认关闭。这是「数据不出站」承诺的技术落点。

### 4.2 输出位置与工作目录解耦

`config.output_root()` 决定报告根目录，解析顺序：

1. 环境变量 `RECONONE_OUTPUT_DIR`（支持 `~` 与变量展开，便于放大盘 / 同步盘）；
2. `<项目根>/runs`。

默认值是**绝对路径**，所以从任何 CWD 启动（双击 GUI、快捷方式、其他目录的终端）都落到同一处。
`config.default_out_dir(domain)` 还会用 `util.safe_name()` 清洗目录名——Windows 目标
`127.0.0.1:39431` 含冒号，直接当目录名会创建失败。

### 4.3 预算是显式的
`config.PROFILES` 里每一档（`fast` / `default` / `deep`）都把 `max_pages / max_depth / max_scripts /
max_js_bytes / max_total_bytes / timeout / budget_seconds` 写死，并回显在 `coverage.limits`。
扫描前就能算出成本，不会跑到一半失控。

### 4.4 证据可溯源
每个端点、密钥、风险提示都带 `{file, offset, snippet}`，`file` 指向 `runs/<domain>/raw/` 下的真实产物。
报告不是裸字符串列表，任何结论都能回到原文核对。

### 4.5 脱敏是五层的（覆盖是默认的，不是靠记性）
1. `util.redact()` 只输出 `masked + sha256_12 + length`（密钥：人工复核需要认得出来）；
2. `jsanalyze.analyze()` 结尾对整个结果做一次**全文替换**——「引用密钥的证据片段」和密钥本身一样会泄露；
3. **响应头与 URL**：`util.scrub_headers()` / `scrub_urls()`。`Set-Cookie` 只抹 `name=value` 的值、
   保留 `HttpOnly/Secure/SameSite/Path/Max-Age`（属性本身就是判定依据），值替换为
   `[redacted:<sha12>:len=n]`——不含原文任何字符，但能证明"我见过这个值"；URL 去掉 userinfo、
   抹掉 `token/key/sig/session…` 的值，**路径保留**（路径就是发现）；
4. **证据片段**：`report._scrub_findings()` 处理 `evidence[].snippet` 里的原始响应头块，
   `_scrub_hypothesis()` 处理假设文本。这两处是真实漏点——`derive_findings()` 会把整块响应头
  存成证据，`authorization:` 与 `set-cookie:` 原文曾从这里绕过前三层。
5. **整份报告的兜底扫描**：`redact.scrub_report()` 在 `assemble()` 把报告交出去之前走**两遍**。
   第一遍按**形状**——`Bearer …` / `Basic …`、JWT、任意 `…token=…` 行内键值、凭据命名的键
   （`password`/`token`/`secret`…，按**精确键名**匹配，因此 `auth_surface` 这类检查项 id
   不会被误杀）、以及所有带 `://` 的字符串。加这一层的理由很直接：`assets.hosts[].url`
   （来自 JS 字面量）、`report.intel`（Wayback 行里可能带 token）、`assets.well_known` 正文
   都不在前四层的覆盖面上，而**以后新加的字段同样不会自动被前四层覆盖**。
   第二遍按**值**——`session.injection.secrets()` 给出本次实际发出的凭据值（长度 ≥6，最长优先），
   在整份报告里逐字替换为 `[redacted:sent-credential]`。形状扫描看不出「你好 `<你的 session id>`」
   是一个凭据，但工具知道自己发过什么：目标把 Cookie/Bearer/自定义头回显到页面标题、正文或响应头，
   都落在这一遍里。`describe()` 只输出名称，`secrets()` 只用于遮蔽，两者都不写出任何值。
   代价只有一次确定性遍历；收益是"新字段默认安全 + 回显默认安全"。

密钥原文只落在 `raw/js/`；`report.json` 全文不含密钥、会话 Cookie 值、URL 凭据。
每份报告的 `meta.redaction` 记录层数、作用范围与例外（`raw/` 保留原始字节用于复核，
且 `runs/` 被 `.gitignore` 排除），因此"脱敏到什么程度"是**可机读核对**的，不是口头承诺。
`tests/test_redaction.py` 用「构造一个全是秘密的响应 → 断言整份 JSON 里一个都不出现」验证，
而不是只断言掩码存在；其中 `TestWholeReportSweep` 专门盯第五层与幂等性。

### 4.6 规则是数据，不是代码
`rules/technologies.json`（47 条指纹）与 `rules/secrets.json`（17 条密钥正则）由 `config.load_rule()`
带缓存加载。加规则不需要改 Python，也不会让 `.py` 体积膨胀。

### 4.7 确定性
`report.py` 里对除时间戳外的全部内容做 canonical JSON 排序后哈希，得到 `deterministic_digest`。
同一目标两次扫描必须得到相同摘要——这让报告可归档、可 diff、可进版本库。

### 4.8 被动与主动是两件事

`intel.py` 是唯一把数据交给第三方的模块，且**不向目标发包**；`triage.py` 的每项检查都带
`mode: passive|active`，画像里给出 `mode_split.passive / mode_split.active`。于是「只用第三方
索引」与「直连目标实测」永远可分辨：前者可离线复现、不惊动目标，后者的每一次请求都记在
`meta.requests` 与作用域守卫日志里。`--no-intel` 可把被动侧整体摘掉，报告不会因此变成空结论，
只会把相关维度标成 `skipped`。

主动侧的口径写在 `profile.weights` 里：`active` / `passive` 权重合计、`active_share_pct`（设计口径）
与 `observed_share_pct`（本次**实际计分**权重中来自主动实测的比例）。`report._probe_stats()` 从
`session.log` 汇总每个状态码的计数，`hard.active_blocking` 只读这份汇总——所以「主动探测进入评分」
不新增任何请求，只把已发出的请求变成证据。依赖是否可用由 `doctor.py` 单独回答（`python -m reconone
doctor`，退出码 4 表示不可用），版本随 `meta.deps` 写进报告，但不进 `deterministic_digest`。

### 4.9 出口与失败分类（2026-11）
传输是 `http.client`，所以代理必须自己接：http 走绝对 URI 转发、https 走 `CONNECT` 隧道、
socks5 走自实现握手（`egress.socks5_tunnel`，不引入 `socksio`）。

失败分类不是给日志看的：`connect-timeout` / `reset` / `refused` 说明**连接没建立**，`auto` 模式只对
这三类做一次回退重试；`tls` 握手错误与 HTTP 状态说明**有东西回答了**，换路由只会得到第二个错答案，
错答案，因此不重试。代理返回 5xx 记 `proxy-error` 而不是当页面——否则「不可达」会变成「可扫」，
整份报告都在评估一个错误页。

`meta.egress` 只写 host:port 与来源，**凭据永不进报告**；它与 `probe_stats` 一样不参与
`deterministic_digest`：描述这次运行，不描述目标。

---


### 4.10 轻量验证与 RoE（2026-11）
扫描产出的是**声明**（这些路径看起来像接口），验证把它变成**证据**：每个端点发一次 `GET`，
服务端答了就标红（可用），答 404/410 或连不上就标灰（不可用）。没有第二个请求，没有请求体，
没有重试——一次判定，判不了就标灰并写明原因。

RoE（`verify.RoE`）是这一阶段的机器可读契约：作用域、允许方法（`GET/HEAD`）、请求上限、排除词
（`logout/delete/reset/…` 这类 GET 也可能有副作用的路径）。每个请求发出前要**同时**通过 RoE 与
`Session.in_scope()`；被拦下的不发送，但会连同原因写进该端点的 `audit`，所以「没验证」和
「验证失败」在报告里长得不一样。`meta.roe` 与 `report.verification.summary` 一起构成可追溯记录。
控制台端点表按 `endpoints[].verified` 上色：可用=红（左侧强调线 + 文字），不可用=灰（整行降透明度）。


### 4.11 会话注入与逐 host 限速（2026-11）

没有身份的扫描只能看到登录墙：401/403 到底是「存在但需要授权」还是「根本不存在」，匿名视角
无法区分。`inject.py` 把 `--cookie` / `--bearer` / `--header`（或 `RECONONE_*` 环境变量）合成一张
**不可变**头表，`Session._attempt()` 里只有一处 `injection.apply(hdrs)`，所以新增的请求路径
不可能忘记带上它，重定向后的每一跳也带着。

凭据是唯一「必须发出、且绝不落盘」的数据，因此 `describe()` 是它进报告的唯一通道：只输出
**头名称、Cookie 键名、是否携带 Bearer**（`meta.session`）。`Authorization: Bearer eyJ…` 出现在
报告里就是一次泄漏；`{"bearer": true}` 才是证据。没有键名的裸 Cookie 片段
（`--cookie "SESSIONTOKEN"`）只记数量 `opaque_cookie_segments`，文本本身不入报告。

**回显是另一半**：`describe()` 管住「我们不写」，`secrets()` + `redact.mask_sent_credentials()` 管住
「目标替我们写」。后者把本次发出的值（≥6 字符、最长优先）在整份报告里逐字替换成
`[redacted:sent-credential]`——页面标题、`well_known` 正文、响应的 `X-Echo-*` 头都覆盖。
`tests/test_redaction.py::TestEchoedCredentialsNeverReachTheReport` 用一个**故意回显**
Cookie/Bearer/ApiKey 的靶站跑完整扫描，先断言服务端确实收到了（否则测试会在「什么都没发」时假通过），
再断言整包 `.json/.md/.txt/.html` 里没有任何一个值。

`rate.py` 解决两个不同问题，共用一份状态：

* **节流**：`--rate N` → 每 host `1/N` 秒间隔。状态按 host 键存，A 站忙不拖慢 B 站。
* **退避**：429/503 是目标在提要求。优先遵守 `Retry-After`，否则 0.5s→1→2→4→8s 指数退避，
  只推后**该 host 的下一次**请求；成功响应重置计数。单次等待有上限（5s）且受扫描时间预算约束，
  防止恶意 `Retry-After: 86400` 把一次扫描拖死。

代价不隐藏：`meta.rate` 记录 `rate_per_s / interval_ms / waits / slept_s / throttled / hosts`，
`session.log[].wait_ms` 记到每个请求，报告 markdown 与 brief 各有一行摘要。`digest` 排除
`session` 与 `rate`——「我们带了谁、跑多快」不是目标的属性，同一目标两次扫描必须得到同一 digest。

### 4.12 Set-Cookie 会话保持（2026-11）

`--cookie` 只能给一个静态身份。真实站点在第一个响应下发会话 cookie，后续每个请求都要带回去；
不带，爬进登录后的区域只会看到登录墙，报告于是把「有内容」写成「401 不可用」——结论错了，
而且错在**低估**目标。

`cookiejar.CookieJar` 是 RFC 6265 的实用子集：`Domain`/`Path` 作用域、`Secure`（只由 TLS 响应设置、
只走 TLS 发回）、`Max-Age`/`Expires`、`Max-Age=0` 删除、上限淘汰（dropped oldest，保持确定性）。
与 `--cookie` 的合并只在一处：`Session._cookie_header()`，**运维显式给的名字优先**——一次扫描里
出现两个身份而不声明，比不带身份更糟。

关键取舍是 `Domain` 的接受规则。没有 public suffix list 就无法证明 `.com` 是公共后缀，所以规则
反过来写：**`Domain` 只能是目标本身或它的子域**，其余一律拒收并计数。代价是某些「友邻域共享
cookie」的站点我们不发（会少一些发现），收益是绝不会把目标的会话交给一个未授权的主机——
宁可少测，也不当 confused deputy。

`meta.session.cookies` 记录 `enabled / received / stored / rejected / live / carried_requests / names`。
值只活在内存里：`tests/test_cookies.py::TestReportedWithoutValues` 跑完整扫描后遍历整包文件，
断言没有任何一个 cookie 值出现在磁盘上。

已知边界：不实现 `SameSite`（我们不是跨站上下文）、不做 cookie 前缀（`__Host-`/`__Secure-`）校验、
不持久化 jar 到磁盘（跨进程复用需要显式重新登录）。

### 4.13 下注判决与授权差分（2026-11）

画像回答"好不好打"，判决回答"要不要下注"。`triage.bet()` 读三样东西——验证结果、端点参数、子域资产——
产出 `report.bet`（阈值 A）：`verdict ∈ {worth, not_worth, withheld}` + `confidence` + 两条判据 + 计数 +
`evidence` + `kill_criteria` + `unknowns`。它是纯函数，同输入同输出，因此进 `deterministic_digest`。

判据一要有**授权差分**才成立：同一个端点，用认证 session 与无凭据 session 各 `GET` 一次。两次回答的
状态与内容差异给出四种结论——`gated`（anon 401/403、authed 2xx：存在但需要身份）、`anonymous_open`
（anon 2xx 且内容与认证态不同）、`same`（两边一样，可能都是公开页或未登录也能看到的壳）、`unknown`。
只有 anon 2xx 才计入判据一。

`withheld` 是这套设计里最容易被误用的状态：它表示**证据不足以下注**（验证被关、或子域没探），而不是
"不值得"。把 withheld 读成 not_worth，会让工具在"看不清"时系统性地劝人放弃——比误报更贵的错误。
所以判决旁边永远并排列出 `unknowns` 与改判条件。

验证侧 v2 的取法：单身份用 `HEAD`（更便宜、无响应体），405/501 时补一次 `GET`；双身份用两次 `GET`。
破坏性动词按**词边界**匹配（`/applications` 不会被 `apply` 误伤），每次请求都受 `RoE.max_requests`
与作用域守卫约束，`audit` 里逐条记录用了几个请求、还剩几个。

## 5. 产物结构

```
runs/<domain>/
  report/
    report.json        机器事实源（schema = recon-one/1）
    report.md          人读版本
    handoff.md         决策摘要：已确认事实 / 未覆盖项 / 下一步 / 停机条件
    brief.md           AI 简报（硬字符预算；在 write_all 之前写出，因此也进 manifest）
    schema.json        随报告附带的 JSON Schema
    manifest.json      产物清单 + 每份文件 sha256_16 + 自校验结果
    endpoints.jsonl    流式，便于 grep/jq
    findings.jsonl
    hypotheses.jsonl
    requests.jsonl    请求台账：method/url/status/egress/error（不含时间，故包级哈希可复现）
  raw/
    js/<sha16>.js          原始 bundle（密钥原文仅存在于此）
    js/<sha16>.pretty.js   按字符串字面量安全换行后的可读版
    maps/*.map             source map 原文
```

**推荐阅读顺序**：
1. `handoff.md` —— 决定「要不要继续、先做哪一条」；
2. `report.json` —— 需要结构时读，字段见 `schema.json`；
3. `raw/` + `evidence[].offset` —— 需要复核某条结论时回原文。

---

## 6. 扩展点

| 想加什么 | 改哪里 |
|---|---|
| 新的技术指纹 / 密钥正则 | `rules/*.json`，零代码改动 |
| 新的探测阶段 | 在 `cli.run_scan()` 里插入，产出并入 `report.assemble()` 的入参 |
| 新的发现类型 | `report.derive_findings()` 里加一个 `add(...)` 分支 |
| 新的假设类型 | `hypotheses.build()` 里加 `add(...)`，排序自动生效 |
| 新的报告字段 | 同步改 `report.SCHEMA` 与 `assemble()`，`validate()` 会自动校验 |
| 新的输入方式 | 复用 `cli.run_scan(on_event=..., cancel=...)`，参考 `web.py` 的 worker 线程写法 |

新增模块时请保持五条不变式：**探测逻辑只依赖标准库**（依赖必须显式声明且启动即校验）、
**依赖方向朝向 `config`/`util`**、**"没观测到"必须表达成 `unknown` 而不是 `fail`**、
**每项结论必须能标出 `passive` 或 `active`**、**进入报告的每个字符串要么不含凭据，要么经过 `util.scrub_*`**。
