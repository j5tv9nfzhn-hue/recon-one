# 安全策略与授权声明（SECURITY）

> 本文件是仓库级的授权边界声明，与 [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md)、
> README 顶部的「授权要求」共同构成使用前提。**使用本仓库任何代码前请先读这三处。**

## 1. 授权要求（不可协商）

本工具是**单域名侦察器**：它会向目标发送请求、读取响应、下载公开脚本，并把结果写成本地报告。

- **只允许**对你拥有、或已获得目标所有者**书面授权**的目标使用。
- 授权必须覆盖：侦察范围（域名与子域）、时间窗口、允许的请求类型与速率、数据处理与留存方式。
- 未获授权对第三方目标使用，在多数辖区可能构成**犯罪**（如《中华人民共和国刑法》第 285 条、
  美国 CFAA、英国 Computer Misuse Act），并可能同时构成民事侵权。
- **不做的事**：不发送攻击载荷、不爆破口令、不做业务逻辑验证、不横向移动。工具的能力边界写在
  [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md) 与 [docs/INTEL.md](docs/INTEL.md)。

授权会写进每一份报告（`meta.authorization` + `report.md` 的「授权声明」一栏 + 简报首屏）：

```powershell
python -m reconone scan --domain example.com --authorized-by "CHG-2026-0417 / 客户书面邮件 2026-04-02"
```

留空不会被拒绝，但报告会明确写「**未声明**」——宁可难看，也不假装有授权。

## 2. 报告本工具自身的漏洞

- 用 GitHub 的 **Private vulnerability reporting**（仓库 `Security` → `Report a vulnerability`），
  或开一个**不含利用细节**的 issue 先约私下沟通渠道。
- 请附：受影响的版本/提交、复现步骤、影响面（例如「报告里残留了某类凭据」）。
- 已知且**不接受**为漏洞的项：报告里保留的 `raw/` 原始产物（这是设计，见下）、
  以及本工具未做鉴权加固的本地控制台（它只监听 `127.0.0.1`，绑定公网属使用者自行决定）。

## 3. 数据处理与脱敏（写进报告，不靠口头承诺）

`report.json / report.md / handoff.md / brief.md` 在写出前经过**五层脱敏**：

| 层 | 处理对象 | 结果 |
|---|---|---|
| 1 | JS 里识别出的密钥 | 全文替换为占位符，原文只留在 `raw/js/` |
| 2 | 响应头 | `Set-Cookie` 值、`Authorization` 等凭据值替换为 `[redacted:<sha12>:len=n]`，**名字与属性保留**（否则「有没有 HttpOnly」就无法判定） |
| 3 | URL | 去掉 userinfo（`user:pass@`）、屏蔽敏感查询参数值，路径保留 |
| 4 | 证据片段 | 头部原文块逐行脱敏后才进 `findings[].snippet` |
| 5 | 整份报告 | 两道：①按**形状**兜底（`Bearer …`、JWT、`token=…`、凭据命名的键、任意 URL 字段）；②按**本次实际发出的凭据值**逐字遮蔽为 `[redacted:sent-credential]` |

报告里同时写出 `meta.redaction`（层数、作用范围、例外），因此可以机读核对。

第 5 层的第二道是「凭据不被目标回显」的兜底：形状扫描看不出「你好 `<你的 session id>`」是一个
凭据，但工具自己知道自己发出过什么。`inject.Injection.secrets()` 提供这些值（长度 ≥6 才登记，
否则遮蔽 `admin` 这类词会毁掉报告事实），`redact.mask_sent_credentials()` 在整份报告里逐字替换，
目标把 Cookie/Bearer/自定义头回显到页面标题、正文或响应头里同样被遮掉。
`meta.redaction.sent_credentials.registered` 记录登记了几个值、`masked` 表明已执行；
`meta.session` 只写头名称与 Cookie 键名，**值本身不出现在 `report/` 的任何文件里**。

**例外（有意为之）**：`raw/js/`、`raw/maps/` 保留原始字节，用于复核某条结论。它们
① 只在本地 `runs/` 下生成，② 被 `.gitignore` 排除，③ 在 `manifest.json` 里单独列出。
需要对外交付报告时，请只交付 `report/` 目录，或先删除 `raw/`。

## 4. 免责

本软件按「现状」提供，不附带任何明示或默示担保。使用者对使用行为及其后果负全部责任；
作者不对任何未授权使用、数据泄露或由此产生的损害承担责任。完整条文见
[docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md) 第 5 节。
