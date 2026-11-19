# 本轮交付：前端探测补强 + Web 控制台


> **状态说明（2026-11 追加）**：本文是某一轮的交付记录，保留当时的判断与数据，**不作为当前事实源**。
> 数字（测试数、模块行数、`runs/free.ai` 示例产物）此后已变化；当前口径以
> `docs/ACCEPTANCE.md`、`docs/ARCHITECTURE.md`、`docs/SCORING.md` 和 `README.md` 为准。
## 1. 先回答的问题：前端探测做完了吗

**部分完成。** 用 `free.ai` 的真实报告（`runs/free.ai/report/report.json`）逐项核对：

| 你说的动作 | 实际状态 | 证据 |
|---|---|---|
| 下载网站前端 | ✅ 已做 | 21 个脚本，20 个落盘（`raw/js/<sha16>.js`），1 个极简化的另存 `.pretty.js` |
| 提取接口 API | ✅ 已做 | 195 个端点，四档置信度：high 57 / medium 38 / low 100，每条带文件+字节偏移+片段 |
| 找 source map | ✅ 已做 | 2 份 `.map`，其中含 `sourcesContent`（可还原原始源码） |
| 找 API 规范 / GraphQL | ✅ 已做 | 本次均为 0，属真实结果（判定为 fail 而非 unknown） |
| **提取请求体字段** | ❌ **原先缺失** | 32 个写方法端点，`params` 全为空 —— 这正是「逆向接口」最该产出的一项 |

丢的那一块正是最贵的那一块：**写端点要传什么字段，原先完全不知道**。
查询字符串能覆盖 GET，但 `POST /api/v1/chat/share/` 这种端点在报告里只是一个不透明的路径。

### 本轮补上

`jsanalyze._extract_bodies()`，三种来源：

```js
body: JSON.stringify({ conversation_id: e, visibility: t })   // fetch / XHR
axios.post("/api/v1/auto-topup/", { amount: o, currency: c })  // 位置参数
fd.append("stripe_token", x)                                   // FormData
```

约束（都写进了测试）：

- 只取**字段名**，不取值 —— 值可能是凭据，落盘即泄露
- `body:` 必须被显式锚定。早期版本用宽松对象匹配，把 `headers:{...}` 里的
  `Content-Type` 当成了请求体字段
- 字段归属于**bundle** 而不是某个端点。压缩代码里字面量和调用点常常不在同一处，
  硬猜关联就是在制造证据
- 结果进 `parameters[].in = "body" | "form"`，评分里与查询参数分开计数

对 `free.ai` 的实测：真实 bundle 里字段名与调用点距离太远，本次提取到 0 个 —— 这是**如实记录**，
不是静默失败。报告里 `opp.params` 现在明确写「请求体字段 0 个」。

## 2. Web 控制台

Tk 窗口已删除，前后端同一进程：

```powershell
python -m reconone ui                          # 启动
python -m reconone ui --report runs\free.ai     # 打开历史报告
```

### 一次性令牌 + 密码

首次运行在**启动它的控制台窗口**打印 `TKN-XXXX-XXXX-XXXX`；浏览器输入令牌后必须立即设密码
（≥10 位，非纯数字/纯字母）。令牌在设密成功那一刻从磁盘删除，之后仅密码登录。

密码存储：PBKDF2-HMAC-SHA256 / 240 000 轮 / 16 字节随机盐。磁盘上不存在明文，也不存在令牌。

### 存储边界

```
recon-one/
├── state/auth.json    # 只有散列与盐
├── runs/<domain>/     # 扫描产物
└── webui/             # 前端（只读）
```

不写 `%APPDATA%`、不写系统盘、不写临时目录、不注册服务。整个目录可搬到任意磁盘。

### 读取时重算

`GET /api/report` 每次都丢弃磁盘上的 `score` 块并用当前模型重算。

这不是洁癖：`free.ai` 的旧报告里存着「维护较好且成本不低，酌情放弃」，模型修好后界面
立刻从文件里读回了这条已作废的结论。**派生物是缓存，读取时必须重算。**
回归测试：`tests/test_web.py::TestServer::test_report_is_rescored_on_read`。

### 界面

- 双色：中性灰阶 + 一个强调蓝；警示用同色语义变体，不引入第三种色相
- 双主题：跟随系统，可切 自动/浅/深，无 JS 时仍按系统渲染
- 克制：无 emoji、无渐变、圆角 8px、间距 4px 步进
- 顶部常驻提示说明评分不覆盖的范围（鉴权、租户隔离、容器/沙箱、业务逻辑）
- 每条结论下方另有「本结论不覆盖：」段

截图：`ui-pair.png`（配对页）、`ui-real-light.png`、`ui-real-dark.png`。

## 3. 顺带修掉的确定性缺陷

远端 `test_ac14_determinism` 间歇失败（约每 4 次 1 次）。根因不是抖动，是设计缺陷：

`Date` 响应头每次请求都变，而它同时出现在两处 —— 证据片段，以及 `deterministic_digest` 的
输入。于是「同目标 → 同摘要」只在同一秒内成立。此前它偶发通过，只是因为两次扫描恰好落在一秒内。

修正：`util.VOLATILE_HEADERS = ("date",)`（`score.py` 与 `report.py` 都从 `util` 取，避免两处漂移），
在摘要计算入口排除；证据片段也不再引用它。
响应头本身仍完整保留在 `assets.http.headers`（它有信息价值），只是不参与摘要。
测试改为**严格模式**（不再在测试里忽略 date），否则等于用测试掩盖缺陷。

修正后远端连续 8 次全绿。

## 4. 测试

| 文件 | 项数 | 覆盖 |
|---|---|---|
| `tests/test_pipeline.py` | 75 | 扫描、评分、判定、请求体提取、确定性（含**请求台账逐行一致**）、传输加固、DNS 应答校验、`--no-js` 端点来源与画像注入、AC25 请求台账与 manifest 哈希、AC26 判决与两次扫描一致、**纯静态站必须判 not_worth（3 项）** |
| `tests/test_concurrency.py` | 11 | 并发与串行同序同结果、共享字节预算、并发度上限 |
| `tests/test_web.py` | 17 | 令牌一次性、弱密码拒绝、存储边界、CSRF、匿名 GET 拒绝、读取时重算、会话持久化、产物增删查、多目标批次、对比接口 |
| `tests/test_intel.py` | 19 | CT 只留目标域、CertSpotter 失败回退 crt.sh、失败折叠成 `status`、存档路径与敏感路径、geo/CVE 默认关闭、站点类型规则、**重试吞掉一次 502**、**子域落地成 `probed:false` 资产**、digest 排除运行遥测 |
| `tests/test_triage.py` | 22 | 权重恒定、指数与带、覆盖率不足拒绝出结论、WAF/版本抬难度、端点面抬价值、`unknown≠fail`、同输入同输出、主动项接线与权重占比；**下注判决 11 项**（匿名命中、置信度、gated 不算暴露、withheld≠不值得、**子域未探不能否决 not_worth**、静态站 not_worth、薄扫描 withheld、IP 无子域维度、改判条件必给、纯函数） |
| `tests/test_doctor.py` | 5 | 五项行为检查全过、版本可读、坏检查被报告而不抛出、CLI 退出码 0/4 |
| `tests/test_redaction.py` | 28 | 四层定点脱敏（头/URL/证据/密钥）+ **第五层两道扫描**：形状（`hosts[].url`、`intel.archive` 行、`well_known` 正文）与**本次发出凭据的值级遮蔽**（页面标题/正文/`X-Echo-*` 头回显都遮掉，最长值优先，短值不登记，幂等）；`meta.redaction` 可机读 |
| `tests/test_egress.py` | 16 | E1 代理全量转发（目标零直连、绝对 URI、CONNECT）、E2 系统代理发现/auto 回退/direct/bypass/PAC 标注、E3 SOCKS5 隧道、E4 失败分类 + 只对连接级失败回退一次 + 代理 5xx 记 proxy-error + 凭据不进报告 |
| `tests/test_verify.py` | 17 | 验证 v2：可用/不可用判定、破坏性动词按词边界跳过（`/applications` 不被误伤）、预算上限、越界被拦并记录、禁用时零请求、只发 HEAD/GET 绝无 POST、HEAD 被拒补一次 GET、**双身份授权差分**（gated / anonymous_open / same）、单身份不假装做过差分、TLS 证书探测走 CONNECT |
| `tests/test_session.py` | 34 | 会话注入到达服务端（含重定向）、注入头大小写无关覆盖、`describe()` 不含凭据值且裸 Cookie 只计数、`secrets()` 只登记 ≥6 字符值并按长度降序、`RECONONE_*`、`--header` 语法校验、逐 host 独立限速、`Retry-After` 与指数退避封顶、成功重置、等待上限与预算收缩、真实 429 退避、整包产物零凭据 |
| `tests/test_cookies.py` | 23 | Set-Cookie 会话保持三层：jar 规则（`Domain`/`Path`/`Secure`/过期/删除/上限、`.com` 与跨域声明拒收、IP 目标不接受 `Domain`、头部顺序稳定）、接线（第二跳自动带 cookie、`--cookie` 同名优先、只发一个 `Cookie` 头、关闭后不发）、端到端（`/app/inner` 由 401 变 200、`meta.session.cookies` 只有名称与计数、整包无 cookie 值、markdown 声明、`use_cookies=False`） |
| **合计** | **267** | `python -m unittest discover -s tests -t .` 全绿（约 105s） |

新增的关键回归：

- `test_strong_headers_do_not_imply_low_value` —— 高维护分不得降级判定
- `test_verdict_states_the_blind_spots` —— 每个结论必须列出盲区
- `test_fetch_json_body` / `test_form_data_append` / `test_headers_are_not_parameters`
- `test_token_is_single_use_and_never_stored_as_plaintext`
- `test_report_is_rescored_on_read` —— 旧结论不得借缓存还魂

本轮（被动情报 / 目标画像 / 非 JS 端点）新增的关键回归：

- `test_unavailable_intel_becomes_unknown_not_fail` —— 第三方超时不得被读成「没问题」
- `test_low_coverage_withholds_the_index` —— 覆盖率不足时**不说**机会指数
- `test_same_input_same_output` / `test_weights_are_internal_and_consistent` —— 画像无随机、无外部输入
- `test_falls_back_to_crt_sh_when_certspotter_fails` —— 单源不可靠时的回退路径
- `TestNoJsMode::test_js_stage_is_skipped_and_no_bundle_is_saved` —— `--no-js` 不落盘任何 bundle
- `TestNoJsMode::test_endpoints_come_from_non_js_sources` —— 端点来自链接/表单/robots，且带 `sources`
本轮（可视化 / 主动权重 / 依赖自检）新增的关键回归：

- `TestRetry::test_transient_failure_is_retried_then_used` —— 一次 502 之后必须重试并采用结果
- `TestRetry::test_a_dead_provider_is_tried_exactly_twice` —— 彻底不通时恰好 2 次，不无限重试
- `TestSubdomainsBecomeAssets::test_ct_hosts_are_listed_as_unprobed_assets` —— 子域落地且标 `probed:false`
- `TestDigestHygiene::test_run_telemetry_is_excluded_from_the_digest` —— 遥测不得污染确定性摘要
- `TestActiveProbeWiring::test_live_surface_and_blocking_are_scored` —— 主动证据真的进分
- `TestActiveProbeWiring::test_skipped_crawl_makes_the_active_check_unknown_not_fail` —— 没爬 = unknown
- `TestActiveProbeWiring::test_weight_mix_is_reported_and_active_carries_the_majority` —— 主动权重占多数
- `test_web.py::...::test_compare_lists_every_run_with_three_decision_axes` —— 对比表需登录且三轴正确
- `test_doctor.py` 5 项 —— 依赖自检失败可见、CLI 退出码 4


## 5. 已知未做

- 深层 JS 反混淆（AST 级）—— 当前是正则提取，混淆代码会漏
- 动态渲染 —— 未跑真实浏览器，Spa 的 XHR 实际请求体抓不到
- 大规模并发枚举 —— API 探测（spec/GraphQL）已并发（6 路，上限 8）；页面爬取与脚本下载仍串行
- `--no-graphql` 时 `opp.graphql` 仍记为 fail（应为 unknown）
- `include_subdomains` 是死参数，定义但无读取点
- **历史漏洞只到「版本被分配过 CVE」**：没有漏洞库落地、没有可利用性判断，也没有指纹到版本的自动关联
  （只在响应头带版本号时才查询，且 `--cve` 默认关闭）
- **被动情报没有限流与重试策略**：单次请求、失败即 `unavailable`；Wayback 慢时宁可给 unknown

前两条正是「后续依赖第三方库」的落点，见 `docs/WEB-UI.md` 第 7 节与 `docs/third-party-libs.md` 第 4 节。

## 6. 本轮追加：会话注入 + 逐 host 限速（2026-11）

匿名扫描只能看到登录墙，401/403 无法区分「存在但需授权」与「不存在」。本轮补上两个模块：

* `reconone/inject.py`：`--cookie` / `--bearer` / `--header`（或 `RECONONE_*`）合成不可变头表，
  在 `Session._attempt()` 唯一一处合并，重定向后仍带；`describe()` 只输出头名、Cookie 键名、
  是否 Bearer → `meta.session`。**值永不落盘**（有目录级测试遍历整包产物断言）。
* `reconone/rate.py`：`--rate N` 逐 host 间隔、429/503 → `Retry-After` 或 0.5→8s 指数退避，
  只推后该 host 的下一次请求，成功即重置；单次等待上限 5s 且受扫描时间预算约束 →
  `meta.rate`、`session.log[].wait_ms`。

顺带修掉两个真实缺陷（都由新测试抓出）：

1. `lstrip("Bearer ")` 按**字符集**剥离，`envtok` 被削成 `nvtok` —— token 首字母落在
   `B/e/a/r/空格` 里就会被改坏；改为精确前缀匹配。
2. `--bearer` 简写会覆盖同一名字的显式 `--header "Authorization: …"`；改为显式头优先。

报告新增 `meta.session` / `meta.rate` 与 markdown「会话与速率（只记录形状，不记录值）」小节，
brief 增加一行摘要；`digest` 排除这两块——「带了谁、跑多快」不是目标属性，同一目标两次扫描
必须得到同一摘要。控制台通过 API body 透传这些字段，界面刻意不提供输入框（避免 token 进入
浏览器存储 / DOM）。

控制台路径同样被覆盖：`tests/test_web.py::TestConsoleSessionPassThrough` 走真实 `/api/scan`，
断言 body 里的 `cookie/bearer/headers/rate` 进入报告（`meta.session.source == "web"`），
且**进度事件流非空**。最后一条是为了钉住本轮修掉的回归：`_run_batch` 曾把
`on_event`/`cancel` 一起丢掉，扫描照样出报告，只是控制台再也没有阶段消息、也无法取消。

### 6.1 凭据不进报告：从「我们不写」到「目标也写不进去」

第一版只保证自己不落盘：`describe()` 输出头名/Cookie 键名/是否 Bearer。审查时补上两处真实缺口：

1. **`--cookie "SESSIONTOKEN"` 这种无键名写法**，旧 `describe()` 会把整段文本当成「Cookie 键名」
   写进 `meta.session` —— 名字看起来无害，内容就是凭据。现在只统计 `opaque_cookie_segments`。
2. **目标回显**：形状扫描看不出「你好 `<你的 sid>`」是凭据。现在第五层脱敏加一道**按值**替换：
   `Injection.secrets()`（长度 ≥6、最长优先）交给 `redact.mask_sent_credentials()`，在整份报告里
   逐字替换为 `[redacted:sent-credential]`；命中计数不进报告（会让 digest 取决于服务端行为），
   只记 `meta.redaction.sent_credentials.registered`。

测试用**故意回显** Cookie/Bearer/ApiKey 的靶站跑完整扫描（`TestEchoedCredentialsNeverReachTheReport`）：
先断言服务端确实收到了这三个值（否则「没泄露」可能只是「什么都没发」），再断言整包
`.json/.md/.txt/.html` 里一个值都搜不到、`report.json` 里留有遮蔽标记、markdown 写明「报告侧脱敏」。
`REDACTION_VERSION` 因此从 `1` 升到 `2`。

### 6.2 Set-Cookie 会话保持（2026-11）

`--cookie` 只能给一个静态身份。真实站点在第一个响应下发会话 cookie，后续请求都要带回去；
不带，爬进登录后的区域只会看到登录墙，报告于是把「有内容」写成「401 不可用」——错在**低估**目标。

`reconone/cookiejar.py`（251 行）实现 RFC 6265 的实用子集：

* `Domain`/`Path` 作用域，`Path` 缺省按请求路径的目录推导；
* `Secure` 双向校验：明文响应不得设置、明文请求不得发送；
* `Max-Age`（优先）/`Expires`，`Max-Age=0` 视为删除；
* 上限 200 个，超限淘汰最旧的，保持「同输入同输出」；
* 线程安全（爬取是并发的），`header_for` 按「路径长者优先 + 名称」稳定排序。

接入点只有两处：`Session._attempt()` 响应后 `store()`、请求前 `_cookie_header()` 合并。
合并规则是**运维显式给的 `--cookie` 同名值优先**——一次扫描里出现两个身份而不声明，比不带身份更糟。

最关键的取舍是 `Domain`：没有 public suffix list 就无法证明 `.com` 是公共后缀，所以规则反过来写，
`Domain` 只能是目标本身或它的子域，其余一律拒收并计入 `rejected`。代价是少数「友邻域共享 cookie」
的站点我们不发，收益是绝不会把目标会话交给未授权主机。（这一条正是测试写错时抓出来的：
第一版用 `scope.endswith("." + domain)`，`Domain=com` 会被接受。）

`meta.session.cookies` 只有 `enabled / received / stored / rejected / live / carried_requests / names`；
值只在内存里活一次扫描。`tests/test_cookies.py` 跑一个**只对持 cookie 者**开放 `/app/inner` 的靶站：
断言该页 200（否则会是 401）、`--cookie` 优先、只发一个 `Cookie` 头、整包文件无 cookie 值、
markdown 写明会话保持、`use_cookies=False` 时不存不发。

### 6.3 请求台账：从"只有计数"到"逐条可核"（2026-11）

审查指出报告只有 `meta.requests` 计数，客户问"你们碰过 `/admin/delete` 吗"答不出。现在每次扫描写
`report/requests.jsonl`：一行一个真实发出的请求，字段 `n / method / url / status / egress / error`。

两个刻意的取舍：

* **不含 `ms` 与 `wait_ms`**。它们每次扫描都不同，而这份文件进 `manifest.json` 带 sha256——
  写进去就等于把"同目标同包"变成假话。
* **按 `(method, url, status, error)` 排序后编号**，不按发起顺序。JS 是并发抓的，谁先出门是调度噪声，
  不是关于目标的事实；排序才能让两次相同扫描产出同一份文件（实测三次运行哈希一致）。

实测抓到的真事：台账里出现了 **POST**——GraphQL introspection。此前"只发 GET"的说法只对验证阶段成立，
台账把这条口误纠正了（README 已知限制已写明）。

测试：`test_ac25_request_ledger_is_complete_and_listed`（字段白名单、编号连续、根 URL 在册、
manifest 里是真实 sha256 而非 `redacted`）+ `test_ac14_determinism` 里追加"两次扫描台账逐行一致"。

### 6.4 长出第一颗牙：授权差分 + 下注判决（阈值 A，2026-11）

目标从"安全交付"改成"精确到敢下注"，所以这一轮不是资格审定，是把判决做实。

**验证 v2（`verify.py` 184→309 行）**

* 单身份：`HEAD` 判存在，比 GET 便宜且无响应体；服务器拒绝 HEAD（405/501）时补一次 `GET`。
* 双身份（注入了 `--cookie/--bearer`）：同一端点 **两次 GET**，认证 session + 一个**无凭据 session**，
  记状态与内容差异 → `gated` / `anonymous_open` / `same` / `unknown`。
* 破坏性动词从 15 个扩到 37 个，并改成**词边界**匹配：`/account/close`、`/orders/9/refund` 跳过，
  `/applications` 不再被 `apply` 误伤（这是上一版真会漏扫的 bug）。
* `RoE.max_requests` 计所有请求（HEAD/GET/双身份），`audit` 逐条记 `requests_used`/`budget_left`。

**下注判决（`triage.bet()`）**

阈值 A：`anonymous_parameterized`（带参数端点无需凭据即可访问）或 `live_subdomain_nonpublic`。
输出 `verdict ∈ {worth, not_worth, withheld}` + `confidence` + 判据 + 计数 + `evidence` +
`kill_criteria` + `unknowns`，进 `report.bet`，markdown 用「## 下注判决」领起。

关键的诚实性设计：`withheld` 不等于 `not_worth`。关掉验证、或子域还没探时，工具**拒绝下结论**，
而不是默认劝退——"看不清就说不值得"会把真正值得的目标劝掉，那比误报更贵。

实测（fixture，带 `--cookie`）：identity `dual`、20 次请求、`authz={same:10}`、判决 `worth/high`、
判据一命中 2 个带参数端点（含 1 个写端点）。单身份扫描同目标同样 `worth`，但 `bet.identity` 写
`anonymous`，让人一眼看出"这次没做差分"。

**还没做的**：判据二（子域探活）仍是 `unknown`，所以判决永远带一条 `unknowns`；控制台还没有判决面板
（只进报告与 markdown）。下一轮就是子域探活 + 定向内容发现。

### 6.5 一次证伪：判决必须能说"不值"（2026-11）

你要求拿纯公开静态站验证"敢说不值"。我先不改代码，直接跑，结果**证伪了**：

```
verdict: withheld
criteria: [('anonymous_parameterized','miss'), ('live_subdomain_nonpublic','unknown')]
```

根因不是判据一判错，而是判据二**恒定 unknown**（子域探活还没实现），而旧规则是
`elif first == "unknown" or second == "unknown": withheld`。于是 `not_worth` 在这套逻辑里
**根本不可达**——工具只会说"值"或"看不清"，正是你担心的情况，只是藏得更深。

修法（`triage.bet()`）：

1. **判据二只能升级，不能否决。** 它探到暴露的存活子域才把判决抬到 `worth`；缺它只写进 `unknowns`。
2. 判据一独占否决权：明确未命中（没有带参数端点 / 全部不可用 / 全被 401、403 拦）+ 扫描够厚
   （验证跑过、未截断）→ `not_worth`。
3. `withheld` 收紧到两种：判据一判不了（验证关掉、带参数端点未验证），或扫描被截断不信负数。
4. CT 状态参与判定：`ok` 且 0 子域 = `miss`（完成的观测）；IP 目标 = `miss`（没有子域维度）；
   只有 CT 未运行/失败、或有子域但未探测才是 `unknown`。

修复后实测（同一个纯静态站，三页 HTML、无表单无参数）：

```
not_worth medium
criteria: [('anonymous_parameterized','miss','没有带参数的端点'),
           ('live_subdomain_nonpublic','miss','IP 目标：没有子域维度')]
report.md: - 判决：**不值**（阈值 A，置信度 medium，身份模型 anonymous）
```

回归：`test_pipeline.py::TestStaticSiteIsJudgedNotWorth`（3 项：站点确实是静态的、判决是
`not_worth`、markdown 写「不值」且不出现「值得打」）+ `test_triage.py` 的
`test_unprobed_subdomains_cannot_block_a_negative` / `test_a_thin_scan_refuses_to_say_not_worth`
/ `test_an_ip_target_has_no_subdomain_dimension`。全量 **267 tests OK**。
