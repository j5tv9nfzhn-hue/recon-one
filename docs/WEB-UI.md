# Web 控制台

原 Tk 桌面窗口已移除。前后端合在一个脚本、一个进程里：启动即同时起服务与界面，结束进程即全部停止。

```powershell
python -m reconone ui
```

## 1. 认证模型

| 阶段 | 行为 |
|---|---|
| 首次运行 | 在**启动它的控制台窗口**打印一次性令牌 `TKN-XXXX-XXXX-XXXX` |
| 输入令牌 | 必须在同一页面立即设置密码（≥10 位，不能纯数字或纯字母，不能是常见弱口令） |
| 令牌寿命 | 设置密码成功的那一刻，令牌从磁盘删除；再启动不会重新下发 |
| 之后 | 仅密码登录，会话 Cookie 为 `HttpOnly; SameSite=Strict`，30 天过期 |
| 密码存储 | PBKDF2-HMAC-SHA256，240 000 轮，每次安装独立 16 字节随机盐 |

为什么令牌走控制台而不走文件：落盘令牌等于把「第一次进门」的凭证放到磁盘上，
任何能读该文件的进程都能抢先完成初始化。控制台只在启动者眼前出现一次。

设计上刻意**不做**的事：不做多用户、不做找回密码。忘记密码就删除
`state/auth.json` 重新配对 —— 这是单机工具，多一条恢复路径就多一个攻击面。

## 2. 存储边界

所有可写状态都在程序目录内：

```
recon-one/
├── state/auth.json     # 凭据（只有散列与盐）
├── runs/<domain>/      # 扫描产物
└── webui/              # 前端静态文件（只读）
```

不写 `%APPDATA%`、不写系统盘、不写临时目录、不注册服务或启动项。
把整个目录拷到另一个磁盘，凭据与历史报告一起搬走。

`--root <dir>` 可以显式改变运行目录，但仍然是「你指定的那一个目录」，
不会散落到多处。

## 3. 读取时重算（重要）

`GET /api/report` **不相信磁盘上的派生结论**，每次都丢弃它们并用当前模型重算：`score`、`profile`、
`bet`、`uncertainty` 与最终的 `decision` 都从同一份证据重新计算；重算 `bet` 之前先用存储的
`verification` 重新 `annotate()` 端点，避免旧报告的 `verified` 被当成 `authz_open`。
`/api/compare` 与 `/api/runs` 同理。

原因是一个真实事故：`free.ai` 的报告在磁盘上带着旧版判定
「维护较好且成本不低，酌情放弃」。改动模型后，界面立刻从文件里读回了这条已经作废的结论 ——
旧结论借着缓存文件还魂。任何评分/判决系统在模型迭代期都会遇到这件事，唯一稳妥的做法是
**把派生物视为缓存，读取时重算**。

对应回归测试：`tests/test_web.py::TestServer::test_report_is_rescored_on_read` 与
`test_compare_lists_every_run_with_three_decision_axes`（旧 profile/bet 不得原样返回）。

## 4. 安全边界

- 默认绑定 `127.0.0.1`。`--host 0.0.0.0` 需显式指定，启动时会打印警告。
- 所有写接口要求会话 Cookie；跨站请求被 `Origin` 校验 + 自定义头 `X-Recon-Request` 双重拒绝
  （HTML 表单无法设置自定义头，因此简单的 CSRF 也被挡住）。
- 静态文件服务做路径穿越检查；响应带严格 CSP、`X-Frame-Options: DENY`、`nosniff`。
- 登录失败 5 次/分钟限流。
- 前端不使用 `innerHTML` 渲染任何服务端数据，全部走 `textContent`；唯一的富文本是
  结论里的 `**强调**`，按 `**` 切分后用 `createTextNode` 重建。

## 5. 界面约定

方向：**Data-dense Pro / Editorial 混合，暗色优先但跟随系统**。

### 为什么暗色是默认

同类工具的用户群强烈偏暗色：约 86% 开发者在主力工作环境用暗色，
约 90% 开发者认为暗色对专业工具是必需的，仪表盘/监控类界面多在弱光环境长时间使用。

但**「默认暗色」必须是系统的推论，不是硬编码**。约 64% 用户希望网站自动匹配系统配色。
因此 `data-theme="auto"` 是初始值，CSS 里 `prefers-color-scheme` 决定实际配色，
手动选择（跟随系统 / 深色 / 浅色）存 `localStorage` 并覆盖它。
无 JS 时仍然正确 —— 已用无 JS 浏览器实测四种组合（JS 开/关 × 系统深/浅）。

### 四条纪律

来自 Vercel 与 Linear 的公开设计规范，也是获奖作品真正的共性：

1. **层级由排版与留白建立，不是由框和阴影。**
   「Do not wrap every section, metric, or comparison in a card.」
   上一版把每块内容都包进卡片 —— 这是「AI 味」最典型的来源。
2. **只在状态与操作上使用彩色。** 状态三档（通过/警告/未通过）全部低彩度；
   强调色只有一个，只给主操作。
3. **所有数值等宽 + 表格数字 + 右对齐。** 比例字体的 1 与 8 等宽不同，列对不齐，
   这是「业余 vs 可信」最廉价的分界线。数值列的表头也一起右对齐。
4. **五个字号档位，一个圆角基准。** 28 / 44 / 13 / 12 / 11；半径 4px 派生。

### 其他约束

- 无 emoji、无渐变、无阴影堆叠、无装饰性动画
- 四个交互态齐备：default / hover / focus-visible / disabled
- 尊重 `prefers-reduced-motion`
- 端点默认只显示 25 条 —— 195 行一次铺开会得到 8000px 的页面，
  那是没做渐进披露，不是「数据密集」

### 醒目提示

范围声明常驻在内容最上方且不可折叠。每份报告另有「本结论不覆盖：」段。
提示不是免责声明，是防止把「外围分高」误读成「内部安全」的机制 —— 这个误读已经发生过一次。

## 6. 参数与请求体

「前端逆向」的目的是在动手之前知道写端点要什么。查询参数只覆盖一半场景，
因此 JS 分析新增了请求体字段提取：

- `body: JSON.stringify({...})` 对象字面量
- `axios.post(url, {...})` / `.put` / `.patch` 的第二个位置参数
- `FormData.append("field", ...)`

只提取**字段名与字节偏移**，不提取值。字段名归到 bundle 而不是某个端点 ——
压缩代码里字面量与调用点常常不在同一处，硬猜关联就是在制造证据。
提取结果写入 `parameters[].in = "body" | "form"`，并在评分 `opp.params` 中与查询参数分开计数。

## 7. 依赖状态与后续方向

**已落地（必需）**：并发抓取层 `reconone/concurrency.py` 用 `httpx`（连接池）+ `anyio`（TaskGroup /
CapacityLimiter）。两者都在 `requirements.txt` 里，且是**硬依赖**：模块直接 import，缺失时
`python -m reconone` 会在启动阶段打印安装命令并退出（退出码 4），不再静默降级。
`lxml` 曾被声明但代码从未 import，已从 requirements 移除。

下一步若继续引入第三方，应当服务于这三件事：

1. **深层 JS 反混淆**（AST 级，替换正则提取）
2. **更大规模的端点枚举**（现为 6 路并发、单目标上限 8）
3. **动态渲染**（真实浏览器跑一遍，捕获 XHR/fetch 的实际请求体）

底线不变：**可离线安装、缺失必须能降级**，否则「拷走文件夹就能跑」这个性质会先于功能丧失。

## 8. 接口鉴权（2026-11 起）

| 路由 | 匿名 GET | 说明 |
|---|---|---|
| `GET /api/state` | 200 | 只回 `configured / authed / version` + `job.{state,progress,stage,elapsed}`；不含 target、out_dir、事件日志 |
| `GET /api/events` | 401 | 事件流含 URL、文件路径与缺口描述，属侦察数据 |
| `GET /api/report` | 401 | 整份报告（评分、端点、findings） |
| `POST /api/*` | 401 / 403 | 需会话 cookie + `X-Recon-Request: 1` + 同源 Origin |
| `GET /api/runs` | 401 | 产物列表（目录名、目标、生成时间、计数、结论、体积） |
| `POST /api/runs/select` | 401 | 切换当前产物；`report` 默认读取它 |
| `POST /api/runs/delete` | 401 | 删除 `runs/<name>/`，需 `confirm: true`，名字必须匹配 `^[A-Za-z0-9._-]{1,120}$` 且解析后仍在 runs 根下 |
| `GET /api/report?run=<name>` | 401 | 按名字读取任意产物（读取时重算评分） |
| `GET /api/compare` | 401 | 横向对比：每份产物的 `worth / ease(100−hardness) / index / band / counts / observed_share_pct`，读取时按当前模型重算评分；最多 20 行 |

`/api/state` 保持匿名可读是刻意的：登录页必须先知道「有没有设置过密码」才能渲染配对/登录。
默认只绑 `127.0.0.1`；`--host 0.0.0.0` 会把登录入口暴露给同网段，仅在确知暴露面时使用。

## 9. 控制台能力（2026-11 当前实现）

| 能力 | 实现 | 自测 |
|---|---|---|
| 实时进度 | 单条自调度轮询：运行中 600ms、空闲 3s；同时取 `/api/state` 与 `/api/events?since=`，增量追加事件、更新总进度与每目标进度行。**不需要刷新页面**，批次结束后自动拉取报告与产物列表 | 浏览器实测 7%→17%→47%→85%→100%，目标行 `running → partial` |
| 侧边栏导航 | 7 个视图（扫描/产物/概览/评分明细/端点/参数/日志）全部可进；切换走 `location.hash`（`#/runs`），刷新后停留在同一视图；没有报告时给出「去扫描」空态卡片，而不是禁用按钮 | 7 个视图逐一断言 `shown/active/hash/title` |
| 视觉与交互 | 设计令牌（色彩/圆角/间距/动效）→ 组件；深色为默认、浅色同为一等公民；三套预设（Tangerine / Soft Pop / Brutalist）切换主色与圆角骨骼；`.view`/`.form`/`.app` 的 `display` 规则与 `[hidden]` 显式对齐 | 浏览器截图核对登录页、扫描页、产物页、概览页 |
| 产物管理 | `GET /api/runs` 列表（目标/时间/端点/发现/**决策**/体积、当前产物高亮）、`POST /api/runs/select` 切换、`POST /api/runs/delete` 删除（二次确认 + 名字白名单 + 解析后仍在 runs 根下）；列表读取时重算 `score/profile/bet/uncertainty/decision` | `tests/test_web.py::TestServer::test_runs_api_lists_selects_and_deletes` |
| 多目标并行 | 一次提交最多 12 个目标；`ThreadPoolExecutor` 按 `RECONONE_TARGET_PARALLEL`（默认 4，上限 8）并行跑 `cli.run_scan`；每个目标独立 out_dir/进度/**判决**，聚合进度取均值 | `TestParallelTargets::test_batch_tracks_every_target` |
| 决策 | 概览首屏：唯一 headline（值得打 / 有面但无出口 / 不值 / 先补证据等）+ 关键因素 + 下一步；数据取 `report.decision`。`score.triage` 不再作为结论，仅在评分章节保留为其信号的边界 | `test_web.py::test_report_is_rescored_on_read`、`test_compare_lists_every_run_with_three_decision_axes` |
| 未知面与下一步 | 独立卡片：带参端点/子域覆盖率、未完成阶段、按影响×请求成本排序的前 5 个动作（含样本与动作说明）、改判路径；数据取 `report.uncertainty`，所有值走 textContent | `tests/test_uncertainty.py`、`test_pipeline.py::FixtureScan::test_ac32_uncertainty_block_ranks_the_next_actions` |
| 免登录 | 首次令牌 → 设置一次密码；会话以 `sha256(sid)` 存 `state/sessions.json`，TTL 30 天，cookie 带 `Max-Age`；设置密码会清空既有会话 | `TestRememberedSessions` 4 项 |
| 目标画像 | 概览视图顶部卡片：worth / hardness / 机会指数 + band + 覆盖率 + 类型/子域/地理/unknown 列表；数值直接取 `report.profile`，前端不二次计算 | `TestNoJsMode::test_profile_is_attached_and_says_what_is_unknown`、`tests/test_triage.py` |

## 10. 画像卡片与五个开关（2026-11）

扫描页第二排的开关全部透传给 `cli.run_scan`，控制台不额外做任何推断：

| 开关 | 默认 | 作用 | 关闭/开启后的报告表现 |
|---|---|---|---|
| 下载前端 bundle | 开（`--no-js` 关） | 关闭后不请求任何脚本，`raw/js/` 不产生 | JS 派生检查（密钥 / sourcemap / 内部主机）为 `unknown`；端点改由链接、表单、robots、sitemap、历史存档提供，带 `sources` |
| 被动情报（CT / 存档） | 开（`--no-intel` 关） | 关闭后不访问任何第三方 | `intel.ct / intel.archive` 为 `skipped`，`worth.subdomains / worth.archive_sensitive` 为 `unknown` |
| 地理位置 | 关（`--geo` 开） | 开启后向 ip-api 查 IP 归属 | 开启才写 `intel.geo`，否则 `disabled` + 原因 |
| CVE 线索 | 关（`--cve` 开） | 开启后按版本号查 NVD | 开启才写 `intel.cve`；没有版本号的产品不查询 |
| 定向内容发现 | 开（`--no-discovery` 关） | JS/spec 前缀 + 技术栈路径 + 少量公共路径，逐条与**同目录前缀**的 404/soft-404 基线比对；上限按 profile | `report.discovery`（baseline/baselines/stats/rows），positive 行以 `content-discovery` 进端点清单但不声称匿名开放；关闭时 `coverage.probes.discovery=skipped` |

卡片与 `report.md` 的「目标画像」一节、`report.json` 的 `profile` 用的是**同一份规则表输出**，
所以三处数字永远一致；band 只用低彩度状态色，不引入新颜色。

画像缺失时（旧报告、或运行被中断）卡片显示「未生成」而不是 0 —— `0` 是一个结论，缺失不是。

## 11. 图表与对比视图（2026-11）

概览页从「一屏数字」变成「一屏判断」，三块可视化都只做同一份报告的投影（前端不推断、不补值）：

| 块 | 形态 | 数据来源 | 降级行为 |
|---|---|---|---|
| 三轴雷达 | JS 构造的 SVG：3 条轴（价值 / 易度 = 100−难度 / 机会指数）+ 25/50/75/100 网格环 | `profile.axes.worth.score`、`profile.axes.hardness.score`、`profile.success.index` | 任一轴为 `null` 时该轴画虚线 + 空心点并标 `—`，**不画成 0**；不足三轴时画开放折线而不是填充面 |
| 端点风险分布 | 环形图 + 图例（首要 / 次要 / 清单） | `endpoints[].priority` | 无端点时显示「无端点（未探测或页面无链接）」并隐藏环形图 |
| 情报落地 | 紧凑三块：子域列表（`source` + 「未探测」）、主动探测强度、依赖版本 | `assets.subdomains`、`meta.probe_stats`、`profile.weights.observed_share_pct`、`meta.deps` | 子域为空时显示 `profile.dimensions.subdomains.status` + `reason`（例如 IP 目标的 `disabled` 说明） |
| 内容发现 | 独立卡片：状态、根基线、候选/探测/存在/受保护/不存在计数、前 8 条 positive 路径；被上限丢弃与截断都明写 | `discovery.status/baseline/baselines/stats/rows` | 未启用时整卡隐藏；基线被拦截/截断时显示原因，不把未探测当成不存在 |
| 未知面 | 独立卡片：覆盖率、未完成阶段、排序后的下一步与改判路径 | `uncertainty.facts/next_actions/verdict_flips` | 无动作时整卡隐藏；操作覆盖率不足只写“未知”，不写成漏洞概率 |

**可访问性**：雷达容器是 `role="img"` 且 `aria-label` 用一句话写出三个数字（含 withheld）；
颜色不是唯一信息载体（数值文本始终存在）；`prefers-reduced-motion: reduce` 时关闭 160ms 淡入。

**对比视图**（`#/compare`，侧栏「对比」）：进入时单次 `GET /api/compare`，表格列出目标、生成时间、
**决策**、未知项数、价值、易度、机会指数（带 band）、子域/端点/发现数、主动实测权重占比；每行「查看」调用
`POST /api/runs/select` 后切回概览。`score/profile/bet` 都在服务端按当前模型重算，评分层标签保留为
tooltip。空态给「去扫描」，接口失败在视图内显示错误文本，行级 `error` 渲染在判决列并禁用该行的
「查看」——**不轮询**，也不把读不出来的产物当成 0 分。

渲染实现全部走 `document.createElementNS` + 呈现属性 + CSS 类：CSP 是 `style-src 'self'`，
所以没有任何内联 `<style>` / `style="…"`，文本一律 `textContent`。
