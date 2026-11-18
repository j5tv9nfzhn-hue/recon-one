# 验收标准

20 条验收项由 `tests/test_pipeline.py`（AC1–AC15）、`tests/test_triage.py`（AC16–AC17）、`tests/test_doctor.py`（AC18）、`tests/test_web.py`（AC19）与 `tests/test_redaction.py`（AC20）自动断言；运行：

```powershell
python -m unittest discover -s tests -t .
```

当前结果：**150 tests OK**（`test_pipeline.py` 68 / `test_concurrency.py` 11 / `test_web.py` 16 /
`test_intel.py` 19 / `test_triage.py` 11 / `test_doctor.py` 5 / `test_redaction.py` 20），全部走本地靶站或纯函数，不访问公网。

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
| AC20 | 第五层兜底脱敏：`assets.hosts[].url`、`report.intel` 的 Wayback 行、`assets.well_known` 正文里的凭据形状都被抹掉，而计数/路径/Cookie 属性原样保留；重复清洗结果不变 | `test_redaction.py::TestWholeReportSweep::test_fields_that_used_to_leak_are_covered` / `test_strict_keys_are_masked_and_already_masked_values_are_left_alone` |

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
