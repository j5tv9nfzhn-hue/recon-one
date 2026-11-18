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
| `redact.py` | 111 | 1 | 第五层兜底脱敏：按形状扫描整份报告（Bearer/JWT/`token=`/凭据键名/任意 URL），并输出可机读的 `meta.redaction` |
| `config.py` | 199 | 8 | 版本号、**授权声明常量**、三档扫描预算、输出根解析、规则加载（带缓存） |
| `http.py` | 275 | 3 | 作用域守卫的 HTTP 客户端，字节/时间预算、手动跟随重定向、解压上限、TLS 证书探测 |
| `dns.py` | 283 | 1 | 自实现 DNS 线格式（A/AAAA/CNAME/MX/NS/TXT/SOA），校验应答源与 txid，无 dnspython |
| `concurrency.py` | 170 | 1 | 并发抓取（httpx + anyio，硬依赖）：同序返回、共享字节预算 |
| `webprobe.py` | 269 | 1 | 首页抓取、安全头按值评分、Cookie 标志、技术指纹、well-known、CORS 实测 |
| `crawl.py` | 161 | 1 | 同源 BFS，受深度/页数限制，抽取链接、表单、内联脚本、注释 |
| `jsanalyze.py` | 520 | 1 | 前端 JS 静态分析：端点/参数/密钥/主机/source map；`from_paths()` 提供非 JS 来源 |
| `apiprobe.py` | 145 | 1 | OpenAPI/Swagger 发现与解析、GraphQL introspection、参数聚合 |
| `intel.py` | 381 | 1 | 被动情报：唯一对外网络出口（可注入），CT 子域 / Wayback 存档 / geo / CVE 逐项 status；单次重试 + 分 provider 超时，永不抛 |
| `triage.py` | 393 | 1 | 目标画像：10 项价值 + 9 项难度规则表（含两项主动实测）、覆盖率门槛、机会指数（非概率）、passive/active 与权重占比 |
| `hypotheses.py` | 165 | 1 | 决策层：把事实转成带前置条件、验证步骤、成本与增益的假设 |
| `score.py` | 782 | 2 | 证据门控评分：18 个原子检查、两轴、覆盖率门槛、triage 规则树 |
| `report.py` | 785 | 1 | 报告组装、画像注入（`profile`）、子域资产、主动遥测、**授权块与五层脱敏**、Schema 校验、markdown/handoff 渲染、manifest |
| `brief.py` | 385 | 1 | AI 简报：授权行 + 画像摘要 + 按决策价值排序、硬字符预算、显式省略计数 |
| `doctor.py` | 148 | 2 | 依赖自检：行为级验证 httpx 客户端、anyio TaskGroup+限流器、DNS 套接字、TLS 校验；不联网 |
| `cli.py` | 514 | 2 | 参数解析（含 `--authorized-by`）、阶段编排、`doctor` 子命令、授权横幅、事件回调、退出码 |
| `web.py` | 708 | 2 | 控制台后端：静态资源 + JSON API（统一鉴权）、多目标并行批次、产物管理、读时重算评分、`/api/compare`、授权声明透出 |
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
          │  └── write_all()     report.json/md/handoff/schema + 3×jsonl + manifest
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
5. **整份报告的兜底扫描**：`redact.scrub_report()` 在 `assemble()` 把报告交出去之前按**形状**
   再走一遍——`Bearer …` / `Basic …`、JWT、任意 `…token=…` 行内键值、凭据命名的键
   （`password`/`token`/`secret`…，按**精确键名**匹配，因此 `auth_surface` 这类检查项 id
   不会被误杀）、以及所有带 `://` 的字符串。加这一层的理由很直接：`assets.hosts[].url`
   （来自 JS 字面量）、`report.intel`（Wayback 行里可能带 token）、`assets.well_known` 正文
   都不在前四层的覆盖面上，而**以后新加的字段同样不会自动被前四层覆盖**。
   代价只有一次确定性遍历；收益是"新字段默认安全"。

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

---

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
