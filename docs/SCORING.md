# 量化评估：方法学与反误报设计

## 为什么不用单一分数

商用安全评级产品（BitSight / SecurityScorecard / UpGuard）最集中的投诉是三条：
**评分不透明**、**误报多**、**资产归属错误**。
典型用户原话是「分数掉 20 分只要一瞬间，修好后要等半年才回升」
以及「我们花大量时间向管理层解释分数为什么变，而底层算法并不透明」。

本模块的设计目标就是让这三条不成立：

| 投诉 | 本模块的应对 |
|---|---|
| 不透明 | 每条检查都输出 `id / weight / status / earned / detail / evidence / source`，可离线复核 |
| 误报 | 未采集 → `unknown`，不计分、不计分母、不视为通过 |
| 归属错误 | 只对本次扫描捕获的数据评分；`localhost` 等自引用显式排除 |

## 两个轴，永不相加

| 轴 | 回答的问题 | 高分含义 |
|---|---|---|
| **维护水平** hygiene | 这个站维护得好不好？ | 配置完善 |
| **可评估机会** opportunity | 这个站值不值得投入？ | 评估成本低 |

合并成一个数字是商用评级最主要的误导来源：
「维护差」和「值得打」是两个独立命题（详见 `目标筛选决策模型.md`）。

> **这里还有第二层，但它是另一件事。** `score.py` 只管这两个轴。`triage.py` 另有一套
> **价值 / 难度 / 机会指数**，回答的是「要不要在此投入人天」，见下方「目标画像」一节。
> 两层之间没有任何相加：hygiene 不参与 `worth`，opportunity 也不参与 `hardness`；
> 画像只在自身内部把 `worth` 与 `100 - hardness` 合成一个**带区间与门槛的指数**
> （`is_probability = false`）。控制台雷达图、`report.md`、`brief.md` 与 `/api/compare`
> 读的都是画像这一层的数，不混用两层的分值。

## 三条硬规则

### 规则 1：无观测，不下结论

```python
# 反例（旧实现）：headers 没抓到就报「缺失 CSP」
if not headers.get("content-security-policy"):
    findings.append("缺少 CSP")

# 本实现：没抓到响应头 → 整组检查标 unknown
if not headers:
    return [check("hdr.unavailable", status=UNKNOWN, ...)]
```

`unknown` 的权重**同时**从分子和分母中移除，因此：

- 不会把「未测量」当成「不合格」而虚假拉低分数
- 也不会把「未测量」当成「合格」而虚假拉高分数

同理，JS 派生的三项（`opp.sourcemap` / `opp.secrets` / `opp.internal`）在
`coverage.probes.js` 不是 `ok`（未跑、失败、`no-scripts`）且没有任何相关观测时判 `unknown`，
而不是 `fail`：没下载过 bundle 就不能写"扫过、没有"。
### 规则 2：值优先于存在性

旧实现用 `if headers.get(name)` 判定，导致：

| 实际值 | 旧判定 | 本实现判定 |
|---|---|---|
| `X-Frame-Options: ALLOWALL` | ✅ 已配置 | ⚠️ weak（点击劫持面未关闭） |
| `CSP: default-src *` | ✅ 已配置 | ⚠️ weak（通配源等于不限制） |
| `CSP: ...'unsafe-inline'` | ✅ 已配置 | ⚠️ weak（内联脚本未禁止） |
| `HSTS: max-age=300` | ✅ 已配置 | ⚠️ weak（窗口不足六个月） |
| `X-Content-Type-Options: foo` | ✅ 已配置 | ⚠️ weak（应为 nosniff） |
| `Referrer-Policy: origin-when-cross-origin` | ✅ 已配置 | ⚠️ weak（跨源仍泄露完整路径） |
| `Referrer-Policy: no-referrer-when-downgrade` | ✅ 已配置 | ✅ ok（仅在降级时不发送） |

`weak` 记半分（`weight * 0.5`），`fail` 记 0 分。

### 规则 3：覆盖率不足不评级

`MIN_COVERAGE_FOR_GRADE = 60%`。低于此值输出 `N/A◇` 而非字母等级。

理由：3/5 项通过 = 60% 分，读起来像 D，但实际是 40% 的权重从未评估过。
「小样本高分」正是评级产品最典型的失真。

## 交付/维护信号（triage）是规则树，不是结论

`score.triage()` 现在只是**交付/维护信号**，不是报告的结论；唯一结论是 `report.decision`（见
`docs/ARCHITECTURE.md` §4.18）。它的输出必定引用**驱动它的检查项 id**，因此分歧可以追溯到具体观测：

```
insufficient-evidence  min(hygiene, opportunity).coverage_pct < 60%，一切结论不可信
        ↓
worthwhile             写方法端点 ≥ 10 个，或 ≥ 3 项机会信号命中 → 有实质业务面
        ↓
low-value              无披露渠道（security.txt）且无任何机会信号 → 找到了也无处交付
        ↓
no-channel             有机会信号但无披露渠道
        ↓
conditional(外围薄弱)  hygiene < 50 且 opportunity ≥ 40 → 进入成本低
        ↓
conditional            其余（外围无结论，必须实测业务层）
```

判定顺序即优先级：`insufficient-evidence` 压过一切。判定**从不**用高 hygiene 分推断"不值得做"
（那只允许在低分时作为"成本更低"的正向提示，见 `score.triage()` 的 docstring）。
早期版本的 `low-yield`（维护好且机会低→酌情放弃）已删除：它把浏览器侧配置当成了业务层结论。

## 权重来源

| 依据 | 用途 |
|---|---|
| Mozilla HTTP Observatory `scoring.md`（2024-02） | 响应头扣分相对权重 |
| RFC 7208 | SPF `-all` / `~all` 判定 |
| RFC 7489 | DMARC 策略强度 |
| RFC 8996 | TLS 1.0/1.1 弃用 |
| 本次观测 | 全部 opportunity 轴检查 |

权重写在 `rules/score.json`（带 `version`），改权重不需要改代码，
且历史报告可用新权重重算——因为评分是 `report.json` 的纯函数。

## 目标画像：10 + 9 项与机会指数（`triage.py`）

这是决策层，不是质量分级。每条检查同样输出 `id / axis / weight / status / earned / detail /
evidence / source / mode`，因此任意一个数字都能追到某个观测值。

### 价值 `worth`（合计 108）

| 检查 | 权重 | mode | 判定 |
|---|---:|---|---|
| `worth.write_endpoints` | 18 | active | POST/PUT/PATCH/DELETE 端点：≥10 pass，3–9 warn |
| `worth.subdomains` | 14 | **passive** | CT 子域：≥8 pass，2–7 warn；未取得 → unknown |
| `worth.api_spec` | 12 | active | 公开 OpenAPI/Swagger 存在 |
| `worth.graphql` | 10 | active | introspection 开放 |
| `worth.parameters` | 10 | active | 具名参数 ≥8 pass |
| `worth.api_surface` | 10 | active | 端点落在 `/api/`、`/v1`、`/rest`、`/graphql` 下（≥10 pass） |
| `worth.archive_sensitive` | 10 | **passive** | 历史存档里的敏感路径（≥5 pass） |
| `worth.disclosure` | 8 | active | 存在 `security.txt` |
| `worth.auth_surface` | 8 | active | 含密码字段的表单 |
| `worth.live_surface` | 8 | active | **本次抓取/爬取直接得到的端点**（≥8 pass，≥2 warn）；`crawl` 与 `js` 都没跑 → unknown |

### 难度 `hardness`（合计 96，越高越难）

| 检查 | 权重 | mode | 判定 |
|---|---:|---|---|
| `hard.waf` | 16 | active | 命中 CDN/WAF 特征头或 `server` |
| `hard.hygiene` | 14 | active | 复用 `score.axes.hygiene`：≥70 难，50–70 中 |
| `hard.stack_age` | 12 | active | 命中 PHP/jQuery/WordPress/IIS 等传统栈 |
| `hard.tls` | 10 | active | TLS1.2/1.3 为「难」，更老为「易」 |
| `hard.version_hidden` | 10 | active | 响应头是否暴露版本号 |
| `hard.subdomain_sprawl` | 10 | **passive** | 子域越多，面越大、越难一次摸清 |
| `hard.mfa` | 10 | active | **恒 unknown**：未持有账号，看不见 MFA |
| `hard.rate_limit` | 8 | active | **恒 unknown**：静态探测看不见限流 |
| `hard.active_blocking` | 6 | active | **已发出请求**里 401/403/405/406/429/503 的占比：≥20% pass；请求数 <5 → unknown |

### 机会指数

```
coverage = min(worth.coverage_pct, hardness.coverage_pct)          # 门槛 60%
index    = clamp(0.55 * worth + 0.45 * (100 - hardness), 5, 95)    # 仅当 coverage ≥ 60
band     : ≥70 high / ≥50 elevated / ≥30 moderate / 其余 low
```

`success.is_probability = false`，`range` 只是档位区间；覆盖率不足时 `index = null`、
`band = unknown`，控制台与雷达图显示 `—` / withheld，**不按 0 计**。

### 主动项口径（`profile.weights`）

| 字段 | 含义 | 当前值（fixture-demo 实测） |
|---|---|---|
| `active` / `passive` / `total` | 权重表里主动项、被动项与合计 | 170 / 34 / 204 |
| `active_share_pct` | 主动项在权重表中的占比（设计口径） | 83.3% |
| `evaluated_active` / `evaluated_total` | 本次实际参与计分的权重 | 130 / 130 |
| `observed_share_pct` | **实际计分权重中来自主动实测的比例**（比设计口径更该看的数） | 100% |

「主动」只指**本次已经发出的请求**：首页、同源爬取、脚本下载、spec/GraphQL 探测、CORS 反射。
`worth.live_surface` 与 `hard.active_blocking` 都**不新增任何请求**——前者数已拿到的端点，
后者对已发出的状态码做比例统计。目录爆破、参数模糊测试、载荷注入属于渗透执行，不在本工具范围，
这条边界随报告写在 `profile.assumptions` 里。

计数口径：价值 10 项里 8 项主动（84 分）、2 项被动（24 分）；难度 9 项里 8 项主动（86 分）、
1 项被动（10 分）。所以一次 `--no-intel` 的运行，`observed_share_pct` 会接近 100%：
结论几乎全部建立在本次实测上。

## 已知边界（不作过度声称）

1. **不判定 CVE 存在性。** 响应头出现 `nginx/1.24.0` 只记为「版本可查询」（`opp.freshness`），
   不推断该版本存在已知漏洞——那需要资产指纹与 CVE 库比对，本模块不做。
2. **不评估业务逻辑缺陷。** 越权、竞态、支付逻辑等需要状态机建模，不在评分范围。
3. **可评估机会 ≠ 存在漏洞。** 高分仅表示「黑盒已部分转白盒，评估成本低」。
4. **分值不可跨目标直接比较**，除非两次运行的 `coverage_pct` 相同。
5. **机会指数不是概率。** 它是 `0.55 × worth + 0.45 × (100 − hardness)` 的合成分，`is_probability=false`，
   `range` 是档位区间而非置信区间；覆盖率 < 60% 时直接不给值。
6. **两个恒为 `unknown` 的项不参与计分**：`hard.rate_limit`、`hard.mfa` 影响极大但静态观测不到，
   固定给一个猜测值正是本项目一直在避免的失真。
7. **`observed_share_pct` 描述的是本次运行**（多少计分权重来自实测），不是目标属性；
   它与 `meta.probe_stats` 一样不进入 `deterministic_digest`，两次扫描可以不同而摘要相同。

## 重新评分

```powershell
# 评分是 report.json 的纯函数，改权重后可离线重算
python -c "import json,sys; sys.path.insert(0,'.'); from reconone import score; r=json.load(open(r'runs\example.com\report\report.json',encoding='utf-8')); print(score.score_report(r)['summary'])"
```
