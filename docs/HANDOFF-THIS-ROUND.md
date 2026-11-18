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
| `tests/test_pipeline.py` | 68 | 扫描、评分、判定、请求体提取、确定性、传输加固、DNS 应答校验、`--no-js` 模式的端点来源与画像注入 |
| `tests/test_concurrency.py` | 11 | 并发与串行同序同结果、共享字节预算、并发度上限 |
| `tests/test_web.py` | 16 | 令牌一次性、弱密码拒绝、存储边界、CSRF、匿名 GET 拒绝、读取时重算、会话持久化、产物增删查、多目标批次、对比接口 |
| `tests/test_intel.py` | 19 | CT 只留目标域、CertSpotter 失败回退 crt.sh、失败折叠成 `status`、存档路径与敏感路径、geo/CVE 默认关闭、站点类型规则、**重试吞掉一次 502**、**子域落地成 `probed:false` 资产**、digest 排除运行遥测 |
| `tests/test_triage.py` | 11 | 权重恒定、指数与带、覆盖率不足拒绝出结论、WAF/版本抬难度、端点面抬价值、`unknown≠fail`、同输入同输出、**主动项接线与权重占比** |
| `tests/test_doctor.py` | 5 | 五项行为检查全过、版本可读、坏检查被报告而不抛出、CLI 退出码 0/4 |
| **合计** | **130** | `python -m unittest discover -s tests -t .` 全绿（约 74s） |

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
