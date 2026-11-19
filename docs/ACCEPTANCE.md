# 验收标准

26 条验收项由 `tests/test_pipeline.py`（AC1–AC15、AC25–AC26）、`tests/test_triage.py`（AC16–AC17）、`tests/test_doctor.py`（AC18）、`tests/test_web.py`（AC19）、`tests/test_redaction.py`（AC20）、`tests/test_egress.py`（AC21）、`tests/test_verify.py`（AC22）、`tests/test_session.py`（AC23）与 `tests/test_cookies.py`（AC24）自动断言；运行：

```powershell
python -m unittest discover -s tests -t .
```

当前结果：**261 tests OK**（`test_pipeline.py` 72 / `test_concurrency.py` 11 / `test_web.py` 17 /
`test_intel.py` 19 / `test_triage.py` 19 / `test_doctor.py` 5 / `test_redaction.py` 28 /
`test_egress.py` 16 / `test_verify.py` 17 / `test_session.py` 34 / `test_cookies.py` 23），全部走本地靶站或纯函数，不访问公网。

## 验收矩阵

| ID | 标准 | 判定方式 | 对应测试 |
|---|---|---|---|
| AC1 | 一次扫描产出完整报告包：`report.json/md/handoff/schema/manifest` + 3 个 jsonl | 文件存在性 | `test_ac1_exit_code_and_artifacts` |
| AC2 | `report.json` 通过随附 JSON Schema 校验 | `reportmod.validate() == []` | `test_ac2_schema_valid` |
| AC3 | 从前端 JS 中提取到端点，且路径归一化（`/users/12345` → `/users/{id}`） | 断言 3 个端点存在 | `test_ac3_js_endpoints_discovered` |
| AC4 | OpenAPI 被发现并解析，其端点与参数并入统一视图 | spec 计数、参数 `tenantId` 存在 | `test_ac4_openapi_parsed_and_merged` |
| AC5 | GraphQL introspection 成功并导出类型统计 | `type_count == 3` | `test_ac5_graphql_introspection` |
| AC6 | source map 被发现，`sourcesContent` 泄露被判定，原文落盘 | 计数 + `raw/maps/` 非空 | `test_ac6_sourcemap_source_leak` |
| AC7 | **密钥脱敏**：`report.json` 全文不含密钥原文；`raw/js` 内含原文 | 双向断言 | `test_ac7_secret_redacted_in_report` |
| AC8 | CORS 反射 + 凭据被识别为 high | finding 类别与级别 | `test_ac8_cors_reflection_found` |
| AC9 | 假设按 `priority_score` 严格降序，`rank` 连续，且至少一条无阻塞 | 排序与结构断言 | `test_ac9_...` |
| AC10 | 每条端点证据的 `file+offset` 指向真实存在的产物 | 文件存在 + offset ≥ 0 | `test_ac10_evidence_offsets...` |
| AC11 | 作用域守卫生效：越界请求被拦截且不发出 | `requests == 0` 且 `off_scope_attempts` 非空 | `test_ac11_offline_scope_guard` |
| AC12 | 页数上限被遵守 | `max_pages=1` 时 `pages <= 1` | `test_ac12_page_cap_respected` |
| AC13 | `handoff.md` 含四个必备小节且 < 200 行 | 字符串断言 | `test_ac13_handoff_is_actionable` |
| AC14 | **确定性**：同目标两次扫描 `deterministic_digest` 相同 | 相等断言 | `test_ac14_determinism` |
| AC15 | `manifest.json` 覆盖全部产物且自校验无错 | 集合包含 + `schema_errors == []` | `test_ac15_manifest_lists_every_artifact` |
| AC16 | 画像只由规则表产生、可解释：权重总额恒定、同输入同输出、未采集维度为 `unknown` 而非 `fail`、覆盖率不足时**不给**机会指数 | `test_weights_are_internal_and_consistent` / `test_same_input_same_output` / `test_unavailable_intel_becomes_unknown_not_fail` / `test_low_coverage_withholds_the_index` |
| AC17 | `--no-js` 仍产出端点面：不下载、不落盘 bundle，端点来自 `html-link / html-form / robots / sitemap / wayback` 且带 `sources`，JS 派生检查为 `unknown` | `TestNoJsMode::test_js_stage_is_skipped_and_no_bundle_is_saved` / `test_endpoints_come_from_non_js_sources` / `test_profile_is_attached_and_says_what_is_unknown` |
| AC18 | 依赖自检回答「这台机器能不能跑」，而不是「库能不能 import」：5 项行为检查、失败保留异常文本、CLI 健康返回 0 / 坏掉返回 4 | `test_every_check_passes_in_this_environment` / `test_a_broken_check_is_reported_and_not_raised` / `test_cli_exits_zero_when_healthy_and_four_when_broken` |
| AC19 | 横向对比接口需登录，每行给出 `worth / ease(100-hardness) / index / counts`（按当前模型重算评分）；子域作为 `probed:false` 资产落地 | `test_web.py::TestServer::test_compare_lists_every_run_with_three_decision_axes` / `test_intel.py::TestSubdomainsBecomeAssets` |
| AC20 | 第五层兜底脱敏：`assets.hosts[].url`、`report.intel` 的 Wayback 行、`assets.well_known` 正文里的凭据形状都被抹掉，而计数/路径/Cookie 属性原样保留；重复清洗结果不变；**本次实际发出的凭据值按字面量遮蔽**（含目标把 Cookie/Bearer/ApiKey 回显到页面标题、正文、`X-Echo-*` 响应头的情形），`meta.redaction.sent_credentials.registered` 可机读 | `test_redaction.py::TestWholeReportSweep` / `TestSentCredentialsAreMaskedByValue` / `TestEchoedCredentialsNeverReachTheReport` |
| AC21 | 出口（E1–E4）：`--proxy` 后所有请求经代理、目标零直连；系统代理从 env/WinINET 发现且 PAC 显式标注不支持；SOCKS5 可用；失败分类为 `connect-timeout/reset/refused/tls`，只有连接级失败回退一次，代理 5xx 记为 `proxy-error` 而不当页面 | `test_egress.py::TestProxyEgress` / `TestSystemProxy` / `TestSocks5` / `TestFailureClassification` |
| AC22 | 验证 v2：单身份 `HEAD` 判存在（405/501 补一次 `GET`）、双身份两次 `GET` 做授权差分；可用（2xx/3xx/401/403/405/429）标红、404/410 与连接失败标灰；RoE 限定方法与总请求数（含 HEAD/GET/双身份）、破坏性动词**按词边界**跳过（`/applications` 不被 `apply` 误伤）、越界请求被作用域守卫拦下且记录；`meta.roe` + `verification.summary`（含 `identity_model`/`authz`）可追溯；TLS 证书探测与请求走同一出口 | `test_verify.py`（17 项）/ `test_pipeline.py::FixtureScan::test_verification_stage_is_bound_and_recorded` |
| AC23 | 会话注入与限速：Cookie/Bearer/自定义头到达服务端且重定向后仍携带；`meta.session` 只含头名与 Cookie 键名（**无键名的裸 Cookie 片段只计数**），`describe()`/`secrets()` 都不写出值，整包产物里搜不到任何凭据；`--rate N` 按 host 独立限速（`wait_ms` 逐请求记账），429/503 按 `Retry-After` 或指数退避（0.5→8s 封顶）推后该 host 的下一次请求，成功即重置；单次等待有上限且受预算约束 | `test_session.py`（34 项）/ `test_web.py::TestConsoleSessionPassThrough` |
| AC24 | Set-Cookie 会话保持：`Domain`/`Path`/`Secure`/`Max-Age` 按 RFC 6265 子集收发，`Max-Age=0` 即删除；**`Domain` 只接受目标或其子域**（`.com` 拒收并计数）；`--cookie` 的同名值优先于 jar；第二跳请求自动带上第一跳拿到的会话（`/app` 由 401 变 200）；`meta.session.cookies` 只记计数与名称，整包文件搜不到任何 cookie 值；`--no-cookies` 关闭 | `test_cookies.py`（23 项） |
| AC25 | 请求台账：`report/requests.jsonl` 逐行记录本次真正发出的每个请求（`n/method/url/status/egress/error`，URL 已脱敏、**不含时间与耗时**），按 `(method,url,status,error)` 排序后编号，因此同目标两次扫描字节一致；该文件进入 `manifest.json` 且带真实 sha256（非 `redacted`）；GraphQL introspection 的 POST 也必须出现在台账里 | `test_pipeline.py::FixtureScan::test_ac25_request_ledger_is_complete_and_listed` / `test_ac14_determinism` |
| AC26 | 下注判决（阈值 A）：`report.bet` 给出 `verdict ∈ {worth, not_worth, withheld}` + `confidence` + 两条判据（`anonymous_parameterized` / `live_subdomain_nonpublic`）+ 计数 + `evidence` + `kill_criteria` + `unknowns`；匿名扫描时"可用且带参数"即命中，注入身份后必须由**授权差分**（anon 2xx）证明；`--no-verify` 或缺子域情报时判 `withheld` 而非 `not_worth`；markdown 以「## 下注判决」领起，两张扫描同输入同输出 | `test_pipeline.py::FixtureScan::test_ac26_bet_sheet_leads_the_report` / `test_ac26_bet_is_stable_across_identical_scans` / `test_triage.py::TestBet`（8 项） |

> AC13 的「必备小节」由测试断言为 3 个（已确认事实 / 未覆盖项 / 建议动作）；`handoff.md` 实际含 5 节，
> 停机条件在第 4 节。文档与断言以**测试**为准。

## 单元测试

| 测试 | 目的 |
|---|---|
| `test_redaction_keeps_shape_not_value` | 脱敏保留长度与哈希、不保留原文 |
| `test_norm_endpoint_collapses_ids` | UUID / 数字 / 模板变量统一归一 |
| `test_pretty_minified_preserves_strings` | 极简化换行不破坏字符串字面量 |
| `test_dns_wire_roundtrip` | 自实现 DNS 报文的构造与解析（含压缩指针） |

除上述 4 条外，`test_pipeline.py` 还覆盖：输出目录布局（保留名/端口/URL）、端点三档优先级、
评分诚实性（unknown≠fail、weak≠pass、证据展示实际返回值）、triage 判决、请求体字段抽取、
`date` 头不污染 digest、Referrer-Policy 逐值判定、JS 未观测时三项检查为 unknown、
多 Set-Cookie 保留、解压上限、DNS 应答源与 txid 校验。`test_web.py` 覆盖配对令牌、密码强度、
匿名 GET 拒绝、读时重算评分；`test_concurrency.py` 覆盖并发与串行的同序同结果、共享字节预算。
`test_intel.py` 覆盖 CT 只留目标域、CertSpotter 失败回退 crt.sh、第三方失败折叠成 `status` 而不抛出、
Wayback 路径与敏感路径识别、geo/CVE 默认关闭与显式开启、站点类型规则命中与未命中；
`test_triage.py` 覆盖权重恒定、机会指数与带信息、覆盖率不足时拒绝出结论、WAF/版本抬高难度、
端点面抬高价值。
`test_session.py` 覆盖：Cookie/Bearer/自定义头到达服务端、注入头大小写无关覆盖调用方头、重定向后仍携带、
`describe()` 不含任何凭据值、`RECONONE_*` 环境变量读取、`--header` 语法错误、逐 host 独立限速、
`Retry-After` 与指数退避封顶、成功重置、单次等待上限与预算收缩、真实靶站上的 429 退避、以及
「整包产物不含凭据」的目录级断言。
`test_redaction.py` 另覆盖**按值遮蔽**：本次发出的凭据被回显进页面标题、`well_known` 正文、
`X-Echo-*` 响应头时都会被替换成 `[redacted:sent-credential]`（最长值优先，避免留下可见尾巴），
短值（`admin`/`acme`）不登记以免毁掉报告事实，重复清洗结果不变；端到端用例跑一个**故意回显**
Cookie/Bearer/ApiKey 的靶站，先证明服务端确实收到了（否则会假通过），再断言整包
`.json/.md/.txt/.html` 里搜不到任何一个值。
`test_cookies.py` 覆盖会话保持的三层：jar 规则（`Domain`/`Path`/`Secure`/过期/删除/上限、
`.com` 与跨域声明拒收、IP 目标不接受 `Domain` 属性、头部顺序稳定、`stats()` 不含值）、
接线（第二跳自动带 cookie、`--cookie` 同名值优先、只发一个 `Cookie` 头、jar 关闭后不发），
以及端到端（只对持 cookie 者开放的 `/app/inner` 必须 200、`meta.session.cookies` 只有名称与计数、
整包文件无 cookie 值、markdown 写明会话保持、`use_cookies=False` 时不存不发）。

## 端到端冒烟（非自动，人工执行）

```powershell
python -m reconone scan --domain example.com --profile fast
python -m reconone validate --report runs\example.com\report\report.json
```

已执行：`valid: true`，`pages=1 / findings=7`，UTF-8 报告可被正确读取（`已确认事实`、`停机条件` 均可匹配）。

被动情报实测（`scan --domain example.com --profile fast --no-js --geo`）：`intel.ct.status=ok`
（`source=certspotter`，2 个子域）、`intel.archive.status=unavailable`（读取超时）→
`worth.archive_sensitive=unknown`；`profile` 为 worth 7.8 / hardness 80.6 / index 13（`low`），
`coverage.combined_pct=80`，且**不存在** `raw/js/`。

## 未纳入自动验收的部分（说明）

- **真实 JS 站点的端点召回率**：需要一份带标注的目标集，属于后续基准工作；当前用 fixture 保证"能抽到、抽得对、可溯源"。
- **DNS 真实解析**：测试只覆盖报文层；联网解析受运行环境影响，故 `--no-dns` 时记为 `skipped` 而非失败。
- **性能上限**：`fast` 档预算 90s 写在 `coverage.limits` 中回显，未做跨平台计时断言（避免 CI 抖动）。
- **第三方可用性**：crt.sh 实测长期 502、Wayback 偶发超时，这些只能在真实网络验证，故不进自动测试；
  测试用注入的 `fetch_json` 固定应答断言「回退」与「失败→unavailable→unknown」两条路径。
