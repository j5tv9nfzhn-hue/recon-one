# recon-one

> ## ⚠ 授权要求（使用前必读）
>
> 本工具只允许对**你拥有、或已获得目标所有者书面授权**的目标使用。运行前请确认三件事：
> ① 授权覆盖本次侦察的**范围与时间窗口**；② 你已了解所在辖区对未授权访问的规定
> （例如《中华人民共和国刑法》第 285 条、美国 CFAA 18 U.S.C. § 1030、英国 Computer Misuse Act 1990）；
> ③ 授权变更或撤回时你会**立即停止**。
>
> 未经授权对第三方目标使用可能构成**犯罪**，并可能同时构成民事侵权。工具的产出（端点清单、
> 密钥线索、历史路径、子域）本身即为敏感信息，须按授权范围保管。
>
> 授权会**写进每一份报告**：`meta.authorization` + `report.md` 的「授权声明」一节 + 简报首屏。
> 用 `--authorized-by "工单号/合同号"`（控制台为「授权依据」输入框）记录依据；留空不会被拒绝，
> 但报告会明确写「未声明」。完整条文见 [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md)，
> 仓库级声明与漏洞报告渠道见 [SECURITY.md](SECURITY.md)。
>
> **数据脱敏**：`report.json / report.md / handoff.md / brief.md` 写出前经过五层脱敏（JS 密钥、
> 响应头凭据、URL userinfo 与敏感参数、证据片段、整份报告形状兜底），并写出可机读的
> `meta.redaction`。例外只有本地 `raw/` 原始产物（复核用，被 `.gitignore` 排除）——
> 对外交付请只带 `report/`。

单域名、本地化、零安装的多合一侦察程序。输入一个域名（或一批域名），输出一份**红队 AI 可直接消费**的结构化报告包。

它的存在理由只有一条：把「AI 花时间在前端 JS 和 API 上做逆向」这件事**一次性做掉**，并把结果变成带证据、带优先级、带停机条件的判断材料，而不是又一份端点列表。

> **先读这一条。** 本工具的评分只覆盖**未认证时可观测的外围配置**：响应头、Cookie 属性、
> TLS 版本、SPF/DMARC。它**不覆盖**鉴权与会话逻辑、租户/对象级隔离、容器/沙箱边界、业务逻辑。
> 外围分低可以说明维护不足；**外围分高不能说明内部安全** —— 实测中这两件事的相关系数接近 0。
> 详见 `docs/WHY-74-VS-15MIN.md`。

## 快速开始

```powershell
cd recon-one
python -m reconone doctor                     # 先确认 httpx/anyio/ssl/dns 真的能用（1 秒，不联网）
python -m reconone ui                         # 启动 Web 控制台（前后端同一进程）
python -m reconone scan --domain example.com --profile default   # 纯命令行
python -m unittest discover -s tests -t .     # 331 项测试（全部本地、不联网）
```

常用开关（`scan`）：`--no-js` 不下载前端 bundle、`--no-intel` 关闭被动情报、`--geo` 查 IP 地理位置、
`--cve` 查版本 CVE 线索、`--proxy http://host:port` 指定出口（支持 socks5://）、`--proxy-from-system`
强制走系统代理、`--direct` 禁止代理（含自动回退）、`--proxy-bypass "localhost,.corp"`；
另有 `--no-verify` / `--verify-max N`（轻量验证）、`--no-discovery` / `--discovery-max N`
（定向内容发现）、`--no-dns`、`--no-graphql`、`--allow-external`、`--out`。
需要登录态时：`--cookie "sid=…"`、`--bearer <token>`、`--header "X-Api-Key: …"`（可重复）；
`--no-cookies` 关闭 Set-Cookie 会话保持；`--no-subdomains` 关闭子域探活（`--subdomain-max N` 调上限）；
限速与退避：`--rate N`（每 host 每秒上限，默认 0=不限）、`--max-backoff S`（默认 8）。

**出口（egress）**：默认 `auto` —— 先直连，只有连接级失败（超时/重置/拒绝）才用系统代理重试**一次**，
并把结果写进 `meta.egress`（mode/type/host/source/fallback_used）。代理若返回 502/503/504，
视为「代理到不了目标」而非「目标应答」，绝不拿错误页当报告。

**会话注入**：`--cookie` / `--bearer` / `--header`（或 `RECONONE_COOKIE` / `RECONONE_BEARER` /
`RECONONE_HEADERS`，换行分隔）会被加到**每一个**请求上，重定向后依然带上。凭据只以「形状」进报告：
`meta.session` 记录头名称、Cookie 键名、是否携带 Bearer，**值永不写入任何产物**（进程参数可见，
真 token 建议走环境变量）。注入了身份之后，401/403 才能按「已认证身份」解读。

**回显也算泄露**：目标可能把我们的 Cookie 印在页面标题或响应头里。形状扫描看不出「你好 `<你的 sid>`」
是凭据，所以第五层脱敏另有一道**按值**的遮蔽——本次实际发出的凭据值（长度 ≥6）在整份报告里被替换为
`[redacted:sent-credential]`，`meta.redaction.sent_credentials` 记录登记了几个值。`raw/` 保留原文用于
复核，交付时只给 `report/`（见 [SECURITY.md](SECURITY.md)）。

**Set-Cookie 会话保持**：站点在第一页下发的会话 cookie 会被记住并带回后续请求（否则爬进登录后的
区域只会看到登录墙）。规则按 RFC 6265 的实用子集：`Domain`/`Path` 限定作用域、`Secure` 只走 TLS
且只由 TLS 响应设置、`Max-Age`/`Expires` 到期即失效、`Max-Age=0` 视为删除。**`Domain` 只能指向
目标本身或其子域**——`Domain=.com` 这类超域声明直接拒收并计入 `meta.session.cookies.rejected`，
避免一次响应把会话 cookie 装进整个 TLD。`--no-cookies` 整体关闭；`meta.session.cookies` 只记
计数与 cookie 名称，值不落盘。

**速率与退避**：`--rate N` 按 **host 独立**计算间隔（A 站慢不拖累 B 站）；收到 429/503 时优先遵守
`Retry-After`，否则指数退避 0.5s→1→2→4→8s 封顶，只推后**该 host 的下一次**请求。单次等待有上限
（5s）、并受本次扫描的时间预算约束，避免被恶意 `Retry-After` 拖死。代价如实记账：`meta.rate`
（waits / slept_s / throttled / hosts）。

只要求 Python 3.9+ 与两个必需依赖（`httpx`、`anyio`）。首次运行先安装：

```powershell
python -m pip install -r requirements.txt     # 必需，缺失时启动会直接报错并提示这条命令
```

没有 Docker，没有外部 API key。

### Web 控制台

前后端在**同一个脚本、同一个进程**里：`python -m reconone ui` 启动，Ctrl+C 或结束进程即全部停止。
默认只监听 `127.0.0.1`，不会在系统里注册服务。

首次运行会在**启动它的控制台窗口**打印一次性配对令牌（形如 `TKN-XXXX-XXXX-XXXX`）。
在浏览器输入令牌后必须立即设置密码；令牌用后即从磁盘删除，之后只用密码登录。
密码以 PBKDF2-HMAC-SHA256（240k 轮、随机盐）存储。

**接口鉴权**：除 `/api/state`（只回 `configured/authed/version` 与进度，供登录页判断状态）外，
所有 API 都要求会话 cookie；`/api/events` 与 `/api/report` 匿名访问返回 401。
即便如此，`--host 0.0.0.0` 仍会把登录入口暴露给同网段，只在确知暴露面时使用。

**多目标并行**：扫描页一次可填最多 12 个目标（每行一个或用逗号分隔），服务端按
`RECONONE_TARGET_PARALLEL`（默认 4，上限 8）并行探测，每个目标独立的运行目录、进度与结论；
控制台的进度条、每目标进度行与事件流都是**实时推送**（600ms 轮询），不需要刷新页面。

**产物管理**：`/产物` 页列出 `runs/` 下所有报告包（目标、生成时间、端点数、下注判决、体积），
可以切换当前查看的产物（服务端会按当前模型重算 `score / profile / bet`），或删除不再需要的目录（二次确认）。

**可视化**：首屏是**下注判决**（值得打 / 不值 / 证据不足 + 两条判据 + 改判条件），其下把三个数字画成
**三轴雷达图**（价值 / 易度 / 机会指数，0–100，未采集的轴显示为空而不是 0），旁边是**端点风险分布
环形图**（按 `primary / secondary / inventory` 三档）与子域、主动探测强度、依赖版本三块紧凑信息。另有 **`/对比`** 视图：把多份产物的价值、易度、机会指数、子域数、端点数和
「主动实测权重占比」并排列出，点一行即可切到该产物——回答「先看哪一个」。
两张图都是同一个报告数据的投影，不含任何前端推断；数据接口是只读的 `GET /api/compare`（需登录）。

**登录**：首次运行用令牌设置一次密码，之后该浏览器 30 天内免登录（会话哈希存在
`state/sessions.json`，会话记录同样不写系统盘）。

**存储位置**：所有状态都在程序目录内 —— `state/auth.json`（PBKDF2 凭据）、`state/sessions.json`
（登录会话的哈希，30 天过期）与 `runs/`。
不写 `%APPDATA%`、不写系统盘、不写临时目录。整个文件夹可以搬到任意磁盘，凭据与报告跟着走。

```powershell
python -m reconone ui --port 8770 --report runs\free.ai   # 直接打开历史报告（读取时重算，见下）
python -m reconone ui --host 0.0.0.0                       # 仅在你确知网络暴露面时使用
```

退出码：`0` 全部探测成功；`2` 部分探测成功（报告仍然可用，未覆盖项写在 `coverage.probes`）；`3` 目标不可达。

## 1. 探测范围

| 层 | 具体探测 | 产出字段 |
|---|---|---|
| DNS | A/AAAA/CNAME/MX/NS/TXT/SOA，SPF、`_dmarc` | `assets.dns.records` |
| 传输 | TLS 证书（SAN/签发者/有效期/指纹）、重定向链、HSTS | `assets.tls` |
| HTTP 面 | 状态、标题、响应头、安全头按值评分、Cookie 标志、技术指纹（47 条规则） | `assets.technology`、`findings[category=headers]` |
| well-known | robots.txt / sitemap.xml / security.txt / crossdomain.xml / favicon | `assets.well_known` |
| 爬取 | 同源 BFS（深度/页数受限），链接、表单（含全部 input）、meta、注释 | `assets.pages`、`assets.forms` |
| **前端 JS** | 下载 bundle、sha256、极简化检测、**按字符串字面量安全换行**、内联脚本 | `assets.scripts` |
| **JS 端点** | `fetch`/`axios`/`$.ajax`/`XHR`/`baseURL`/`endpoint` 配置/绝对 URL/相对路径，四档置信度 | `endpoints[source=js-call\|js-config\|js-literal\|js-string]` |
| **JS 密钥** | 17 条规则（AWS/GCP/Stripe/GitHub/JWT/私钥/基本认证 URL…），熵过滤 + 脱敏 | `secrets` |
| **source map** | 探测 `sourceMappingURL`，下载 `.map`，解析 `sources`，判定 `sourcesContent` 是否泄露源码 | `assets.scripts[].sourcemap` |
| **JS 风险模式** | `innerHTML`/`eval`/`postMessage`/`localStorage` 存 token/debug 开关/URL 内凭据 | `findings[category=js-hint]` |
| 主机面 | 前端引用的外部主机与**内部命名空间**（`.corp/.internal/10./172.16-31`…） | `assets.hosts` |
| **API 规范** | 12 条常见 OpenAPI/Swagger 路径，解析 paths、方法、参数、securitySchemes | `specs`、`endpoints[source=openapi-spec]` |
| **GraphQL** | 对候选端点发起 introspection，导出类型/字段数 | `graphql` |
| **参数面** | JS + 表单 + 规范三源聚合，去重并记录归属端点 | `parameters` |
| CORS | 用外部 Origin 实测反射与 `Allow-Credentials` | `findings[category=cors]` |
| **决策层** | 由以上事实生成假设：前置条件、验证步骤、成功信号、成本、信息增益、是否受阻 | `hypotheses` |
| **非 JS 端点来源** | 链接、表单 action、robots、sitemap、Wayback 路径，与 JS 结果按路径合并并标 `sources` | `endpoints[source=html-link\|html-form\|robots\|sitemap\|wayback]` |
| **被动情报** | CT 日志子域（CertSpotter 主 / crt.sh 回退）、Wayback 快照与历史敏感路径、可选 geo 与版本 CVE 线索 | `intel.ct / intel.archive / intel.geo / intel.cve` |
| **目标画像** | 10 项价值 + 9 项难度规则表 → 价值/难度/机会指数（非概率），逐项标 `passive` / `active`，并给出主动权重占比 | `profile`、`profile.weights` |
| **轻量验证** | 单身份 `HEAD` 判存在（405/501 补一次 GET），双身份两次 `GET` 做**授权差分**（anon 2xx + 内容差异 = 匿名开放）；`authz_open` 只在有观测时写入——单身份按状态（2xx/3xx 才算），双身份按 `anonymous_open` 标签；RoE 方法/上限 + 作用域守卫双检，破坏性动词按词边界跳过 | `verification`、`verification.summary.authz`、`endpoints[].authz_open`、`meta.roe` |
| **TLS 证书** | 与请求走同一出口（直连 / CONNECT / SOCKS5），不再有隐藏直连 | `assets.tls.egress`、`assets.tls` |
| **主动探测评分** | 只统计本次已经发出的请求：可达端点（`worth.live_surface`）、被拦截比例与 429 次数（`hard.active_blocking`）；不新增任何爆破/模糊测试 | `meta.probe_stats`、`profile.checks` |
| **会话与限速** | 凭据按形状记录（头名/Cookie 键名/是否 Bearer，值不入盘）、每 host 独立限速、429/503 按 `Retry-After` 或指数退避 | `meta.session`、`meta.rate` |
| **Set-Cookie 会话保持** | 记住站点下发的会话 cookie 并带回后续请求；`Domain` 只接受目标或其子域（`.com` 直接拒收）、`Secure` 双向校验、`Max-Age`/`Expires` 与删除语义 | `meta.session.cookies` |
| **子域探活** | CT 子域逐个 `GET /`（HTTPS 失败按传输层错误回退一次 HTTP），判定 `gated`（401/403 或登录墙）/ `exposed`（2xx 且主机名或标题像内部系统）/ `public` / `dead`；**只探目标或其子域**，越界只记录不发请求 | `assets.subdomains[].probed/label/non_public`、`meta.subdomains` |
| **定向内容发现** | 候选只来自三处：已观测端点的目录前缀、技术栈规则表、少量公共路径；每个目录前缀先请求一条**确定性不存在路径**做基线，候选与同前缀基线比对，识别 soft-404（根基线看不出 `/api/*` 的 catch-all）；上限按 profile（fast 20 / default 80 / deep 160）或 `--discovery-max`，不做字典 | `discovery` 块（baseline/baselines/stats/rows）、`coverage.counts.discovered`、`endpoints[sources=content-discovery]` |
| **依赖自检** | `python -m reconone doctor` 行为级验证 httpx/anyio/ssl/dns；每次扫描把版本写进报告 | `meta.deps`、CLI 退出码 4 |

**不做的事**（边界清晰）：不发送攻击载荷、不爆破口令、**不做目录爆破**（内容发现只探测有界候选）、
不做业务逻辑验证、不横向移动。主动路径**不调用任何第三方 SaaS**；被动的 CT / Wayback / 可选 geo / CVE
只是把已公开的数据拉进本地，`--no-intel` 可整体关闭。它只测绘与推断。

### 1.1 不下载前端也能发现接口

接口发现不必依赖逆向 bundle：五条**不执行 JS** 的来源（页面链接、表单 action、robots、sitemap、历史存档）
和 JS 分析结果按路径合并，每个端点带 `sources` 字段说明来自哪里。`--no-js` 整体跳过 bundle 下载与逆向，
此时不会产生 `raw/js/`，JS 派生的检查（密钥、sourcemap、内部主机）标 `unknown` 而不是 `fail`。
两条路径的逐条对照见 [docs/INTEL.md](docs/INTEL.md)。

### 1.2 目标画像：值不值得打、好不好打

`profile` 完全由规则表算出（无模型、无学习，同输入同输出）：**价值** 9 项（写方法端点、API 规范、GraphQL、
参数面、子域、历史敏感路径、披露入口、认证面…）、**难度** 8 项（WAF、维护分、TLS、版本隐藏、技术栈年龄、
子域泛滥），两项各自带覆盖率；覆盖率 < 60% 时**不给机会指数**。机会指数 = `0.55×价值 + 0.45×(100−难度)`，
输出 `index / band / range` 且 `is_probability=false` —— 它是可解释的机会排序，不是漏洞概率。
`rate_limit` 与 `mfa` 静态不可观测，永远是 `unknown`。详见 [docs/INTEL.md](docs/INTEL.md)。

### 1.3 下注判决：worth / not_worth / withheld

画像解决"好不好打"，**判决**解决"要不要下注"。报告顶层有 `bet` 块（阈值 A），两条判据：

- `anonymous_parameterized`：**带参数**的端点**无需凭据**即可访问。没有注入身份时本次扫描本身即匿名，
  但“匿名”不等于“可访问”：只有 2xx/3xx 才算命中，401/403/405/429 只证明端点存在（`authz_open=false`）；
  注入了 `--cookie/--bearer` 时用**两次 GET**（认证 / 匿名）比对，只有匿名侧 2xx/3xx **且内容与认证态
  不同**（`anonymous_open`）才算；两边完全相同的 `same` 不算命中。
- `live_subdomain_nonpublic`：**探到的**存活子域暴露非公开面（`gated` 或 `exposed`）。没探就记 `unknown`，
  探了没暴露记 `miss`——这条判据只能把判决抬到 `worth`，不能否决。

**判决规则（两次证伪驱动的修正）**：判据一是唯一能否决的判据。它必须**明确**未命中（没有带参数端点 /
全部不可用 / 全部未证明匿名开放），且扫描够厚（验证跑过、未被截断）→ `not_worth`。判据二**只能升级**：
探到暴露的存活子域才把判决抬到 `worth`，缺它不会把 `not_worth` 变成 `withheld`。

早期版本把"子域未探测"记成 `unknown` 并据此判 `withheld`，结果 `not_worth` **永远不可达**——纯公开
静态站也会被判"看不清"。修复后静态站稳定输出 `not_worth`，并有端到端回归钉住它
（`TestStaticSiteIsJudgedNotWorth`）。`withheld` 现在只剩两种含义：判据一判不了（验证关掉、带参数端点
未验证），或扫描太薄不信负数（被截断）。注意“截断”只指字节/时间预算打断，**单个 404 脚本不会**把
一次完整扫描改判为 `withheld`。报告永远并排列出判据、计数、`kill_criteria` 与 `unknowns`。

顺带说明验证引擎的取法：单身份用 `HEAD` 判存在（比 GET 便宜、无响应体），服务器拒绝 `HEAD`（405/501）
时补一次 `GET`；双身份用两次 `GET` 做授权差分。破坏性动词（`close/void/refund/apply…`）按**词边界**
跳过，`/applications` 不会被 `apply` 误杀。验证预算有限（默认 40 次请求，双身份每端点 2 次），所以队列
按 **testability** 排序：带参数、写方法、高置信端点先验证，同一路径的 JS 与 OpenAPI 结果合并后只花一次。

并发 API 探测（OpenAPI/GraphQL）也遵守同一套纪律：注入头、cookie jar、作用域检查、重定向逐跳、
限速与失败台账都在；一旦启用 `--proxy` 或 `--rate`，这条路径直接退回串行 `Session.request`，
宁可慢一点，也不让请求走另一条路由。

### 1.4 未知面与下一步：把"未知性"变成可执行动作

判断"值不值得打"的前提是承认还有没看到的面。报告顶层 `uncertainty` 块把这句话变成可核对的数据：

- `facts`：带参端点已判定 `x/y`（`parameterised_checked_pct`）、子域已探 `x/y`、未完成阶段、是否截断。
- `unknowns`：每个未闭合项带 `impact`（high/medium/low，**序数策略，不是概率**）、`count`、`cost_requests`
  （按本次身份与端点数的请求估算）、`affects`（判据一/二）、`could_change_verdict_to`、`action`、`samples`。
- `next_actions`：按 **影响降序 → 请求成本升序 → id** 排序的前 5 项。第一个动作是最便宜的高影响未知，
  不是最长清单。
- `verdict_flips`：当前判决的改判路径（`withheld/not_worth → worth`、`withheld → not_worth`、
  `worth → not_worth`），写明条件、关联未知项与成本。

典型项：未验证的带参端点、缺少匿名访问判定的端点、未探的 CT 子域、验证关闭、JS 跳过、内容发现未跑/被
基线拦截/截断、未知方法端点、低置信端点。`worth` 还会附一条"确认命中仍可交付"的复核动作。
它是纯函数，进 `deterministic_digest`；`report.md`、`handoff.md`（§2.1）、`brief.md` 与概览卡片读的是
同一份排序。

## 2. 报告格式与交付方式

一次扫描产出一个自包含目录：

```
runs/<domain>/
  report/report.json        # 唯一机器事实源，schema = recon-one/1
  report/handoff.md         # 决策摘要：已确认事实 / 未覆盖项 / 下一步 / 停机条件
  report/brief.md           # 简报：目标画像 + 端点表（硬字符预算，给消费方一次读完）
  report/report.md          # 人读版本
  report/schema.json        # 随报告附带的 JSON Schema
  report/manifest.json      # 全部产物清单 + 每份文件的 sha256_16 + 校验结果
  report/endpoints.jsonl    # 流式，便于 grep/jq
  report/findings.jsonl
  report/hypotheses.jsonl
  report/requests.jsonl     # 请求台账：本次真正发出的每个请求（含失败尝试，method/url/status/egress/error）
  raw/js/<sha16>.js         # 原始 bundle（密钥原文仅存在于此）
  raw/js/<sha16>.pretty.js  # 换行后的可读版本
  raw/maps/*.map            # source map 原文
```

交付给 AI 的推荐顺序：

1. 读 `report/handoff.md` —— 决定「要不要继续、先做哪一条」；先看 `profile`（`report.json` 或 `report.md` 的「目标画像」一节）再决定值不值得投入。
2. 需要结构时读 `report/report.json`，字段约定见 `schema.json`。
3. 需要复核某条结论时，用 `evidence[].file` + `offset` 回到 `raw/` 定位原文。

三条设计约束：

- **可溯源**：每个端点/密钥/提示都带 `{file, offset, snippet}`，不是裸字符串。
- **可脱敏**：报告正文永不出现密钥原文，只有 `masked` + `sha256_12`；原文仅落在 `raw/`，且整个结果集在离开内存前做一次全文替换，防止证据片段泄露密钥。
- **可判定**：`coverage.probes` 明确区分 `ok / partial / none-found / no-scripts / unreachable`，所以「没发现」和「没执行」在报告里长得不一样。

## 3. 本地化与轻量化约束

| 约束 | 实现 | 可验证方式 |
|---|---|---|
| 体积 | 30 个 Python 模块 + 4 个规则 JSON，源码约 481 KB | `python -c "import glob,os;print(sum(os.path.getsize(f) for f in glob.glob('reconone/*.py')))"` |
| 依赖（必需） | 只用标准库实现探测逻辑；DNS 自行实现 UDP/TCP 查询（无 dnspython）。`httpx` + `anyio` 是并发的必需依赖，缺失时启动即报错并提示安装命令 | `python -m pip install -r requirements.txt`；`tests` 全绿 |
| 无外部服务 | 所有请求直达目标；默认禁止跨域请求 | `--allow-external` 关闭时 `scope_blocks` 拦截 |
| 单一入口 | `python -m reconone scan` | — |
| 预算可控 | `max_pages / max_depth / max_scripts / max_js_bytes / max_total_bytes / timeout / budget_seconds` 全部显式，`fast` 档 90s | `coverage.limits` 回显 |
| 确定性 | 排序、稳定 ID、`deterministic_digest`（排除时间戳） | 同目标两次扫描 digest 相同 |
| 无状态、可离线复用 | 产物是纯文件，可归档、可 diff、可进 git | — |

## 4. 验收标准

完整表格与逐条对应测试见 [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)。32 条验收项由测试断言。当前全仓 **331 tests OK**（`test_pipeline` 83 / `test_concurrency` 17 / `test_discovery` 13 / `test_uncertainty` 7 / `test_web` 17 / `test_intel` 19 / `test_triage` 26 / `test_doctor` 5 / `test_redaction` 28 / `test_egress` 16 / `test_verify` 19 / `test_session` 35 / `test_cookies` 24 / `test_subdomains` 22），`python -m unittest discover -s tests -t .` 可直接复现。

## 5. 已知限制

- **单身份/双身份**：默认匿名扫描（此时"匿名可访问"是事实）；`--cookie/--bearer/--header` 注入身份后，
  验证阶段自动切到**双身份**（另开一个无凭据 session 做对比）。两种模式下"匿名可访问"的判定口径不同，
  报告用 `verification.summary.identity_model` 明示，`bet.identity` 复述一遍，不让人猜。
- **cookie 规则是子集**：不实现 `SameSite`（我们不是跨站上下文）、不做 public suffix 推断，
  所以 `Domain` 只接受目标本身或它的子域，宁可拒收也不当 confused deputy。
- **`report/` 不含凭据，`raw/` 例外**：`report.*` 里连回显的凭据都被遮掉，但 `raw/js`、`raw/maps`
  保留原始字节用于复核（见 [SECURITY.md](SECURITY.md)）；交付时只给 `report/`，或先删 `raw/`。
- **无渲染引擎**：不执行 JS，纯静态分析。SPA 的动态接口只能通过 bundle 字面量与 source map 获得。
- **技术指纹**为规则匹配，会误报（例如同源 CDN 头）。
- **GraphQL introspection** 属主动探测（**是 POST**），可用 `--no-graphql` 关闭；`--no-verify` 只停验证阶段，
  不会停它。请求台账如实记录方法，所以"这次到底发了什么"可核对。
- **eTLD+1** 内置简化规则，未加载 public suffix list。
- 端点方法推断（`GET?`）来自邻近上下文，置信度低于规范来源。
- **内容发现是有界的观测**：候选来自已观测端点前缀 + 技术栈表 + 少量公共路径，不是字典；同目录基线能挡住
  catch-all/soft-404，但动态渲染、多语言跳转与带随机内容的页面仍可能造成漏判或误判。positive 行是
  `confidence=low` 的端点，且**不声明匿名开放**。
- **被动情报依赖第三方可用性**：crt.sh 实测长期 502，故 CertSpotter 为主、crt.sh 为回退；Wayback 可能超时。
  任一失败都只在报告里写 `unavailable` + 原因，并把对应检查降为 `unknown`，不会伪造「干净」结论。
- **geo 与 CVE 默认关闭**（`--geo` / `--cve`）：前者把目标 IP 交给 ip-api，后者依赖 NVD 且无 key 严格限流。

## 6. 目录

```
recon-one/
  reconone/    cli(编排) config http dns webprobe crawl jsanalyze apiprobe intel(被动情报)
               triage(画像) uncertainty(未知面/改判路径) hypotheses(决策) score(评分)
               report(组装) brief(简报) verify(轻量验证) discovery(定向内容发现)
               inject(会话注入) cookiejar(Set-Cookie) rate(限速退避) egress(出口)
               redact(脱敏) doctor(依赖自检) concurrency(并发) auth(凭据) web(控制台) util
  rules/       technologies.json (47 条), secrets.json (17 条), score.json (权重与评级),
               discovery.json (技术栈/公共路径候选，非字典)
  tests/       fixture_server.py, test_pipeline.py, test_concurrency.py, test_discovery.py,
               test_uncertainty.py, test_web.py, test_intel.py, test_triage.py, test_doctor.py,
               test_redaction.py, test_egress.py, test_verify.py, test_session.py, test_cookies.py
  docs/        ARCHITECTURE.md, INTEL.md（被动/主动与画像算法）, ACCEPTANCE.md, SCORING.md,
               WEB-UI.md, RESEARCH.md, AUTHORIZED-USE.md 等
  SECURITY.md  仓库级授权声明 + 本工具漏洞报告渠道 + 五层脱敏范围
  runs/        扫描产物（运行时生成，按目标域名分目录）
  state/       auth.json（PBKDF2 凭据）、sessions.json（会话哈希，30 天）
```
