# 开源侦察工具能力边界调研

调研时间：本轮任务内实测抓取（GitHub API + raw README），非凭记忆归纳。
证据文件：会话 scratch `research/*.md`（原始 README），结论以关键词命中统计为准。

## 1. web-check（Lissy93/web-check）

- 定位：`All-in-one OSINT tool for analysing any website`，35.5k stars，默认分支 `master`。
- 源码结构 `api/` 目录经 GitHub Contents API 枚举，**共 40 个检查项**：

  `archives, block-lists, breaches, caa-records, carbon, cookies, dns-server, dns, dnssec,
  firewall, get-ip, headers, hsts, http-security, linked-pages, location, mail-config,
  mixed-content, ports, quality, rank, redirects, robots-txt, screenshot, security-txt,
  shodan, sitemap, social-presence, social-tags, ssl, status, subdomains, tech-stack,
  threats, tls-connection, tls-labs, trace-route, trackers, txt-records, whois`

- 能力边界：
  - 每个检查项都是**对目标的一次性黑盒观测**（请求一次、返回一个结论）。
  - 40 项里**没有任何一项做 JavaScript 静态分析**：不下载 bundle、不解析 source map、不做字符串/端点/密钥挖掘。
  - `linked-pages` 只做浅层链接提取，不等于 API 面测绘。
  - 无认证态概念：不持有会话，无法进入登录后的功能面。
  - 依赖多个第三方 SaaS（Shodan、IP 定位、排名、威胁情报）→ 数据出站，不适合授权项目内的目标信息外传。
  - 输出为**展示型 JSON/页面**，没有面向自动化消费的 schema、没有证据溯源、没有优先级。

## 2. 能力关键词命中统计（README 全文正则）

| 关键词 | 命中项目 |
|---|---|
| `openapi\|swagger` | nuclei(1)、reconftw(1) |
| `graphql` | katana(2)、reconftw(4) |
| `sourcemap\|source map` | reconftw(1) |
| `hypothes\|prioriti[sz]` | **无任何项目命中** |

即：OpenAPI/GraphQL 在这批工具里最多是"模板里的一个字符串"，不是一等发现能力；source map 只有 reconftw 提过一次；**假设生成与优先级排序在所有工具中均不存在**。

## 3. 单点工具（各自只覆盖一个维度）

| 工具 | 覆盖 | 边界 |
|---|---|---|
| subfinder | 被动子域 | 只出子域，不碰 HTTP |
| naabu | 端口 | 只出端口 |
| httpx | 存活/状态/标题/技术栈 | 单请求探针，不解析正文 |
| webanalyze | 技术指纹 | Wappalyzer 规则移植，只做指纹 |
| katana | 爬取 | 有 `-jc`(JS 内端点)、`-jsl`(jsluice)、`-fx`(表单提取)、`-kf`(known files)，但**无 source map 挖掘、无 API 规范发现、无假设层** |
| LinkFinder | JS 端点 | 仅正则抽 URL，输出 HTML/文本 |
| SecretFinder | JS 密钥 | 基于 LinkFinder，仅密钥 |
| xnLinkFinder | JS 端点+参数+密钥 | 单机脚本，仍是"抽字符串"，无 schema/无证据偏移 |
| gau / waybackurls | 历史 URL | 依赖外部档案，不含实时 JS |
| webanalyze / Corsy | 指纹 / CORS | 单点 |
| amass | DNS/资产测绘 | 只到资产层 |
| nuclei | 模板化漏洞验证 | 需要已知入口；不做面测绘 |
| spiderfoot | 模块化 OSINT | 200+ 模块，重，输出扁平，无 API 面 |
| reconftw / bbot / rengine / Sn1per | 编排器 | 依赖数十个外部二进制 + Docker/DB/UI；安装与维护成本远超"轻量本地化" |

## 4. 结构性缺口（本项目的设计依据）

1. **没有工具把"前端 JS"当作一等情报源**：JS 是唯一能免费获得"未公开端点 + 参数名 + 内部主机 + 构建结构"的资产，而上述工具要么只做正则抽取（无归一化、无证据、无 source map），要么完全不碰。
2. **没有 API 面测绘**：OpenAPI/Swagger 规范发现、GraphQL introspection、参数聚合、认证模型推断，四项均无项目覆盖。
3. **没有"写报告给 AI 用"的格式**：所有输出是给人看的展示或给 grep 用的行文本，缺少稳定 schema、证据溯源、覆盖度声明与失败原因区分。
4. **没有决策层**：全部工具止于"发现了什么"，没有一个回答"下一步该验证什么、为什么、代价多大"。这正是前面讨论中拖慢渗透的那一层。
5. **重量级与本地化冲突**：能力齐全的几个（reconftw/bbot/rengine/spiderfoot）都要求几十个外部依赖与容器运行时，与"轻量、可离线、可嵌入现有流程"直接矛盾。

结论：需要一个**单文件级依赖、无外部服务、覆盖 JS 与 API 面、输出带证据与优先级的结构化报告**的程序。这就是 `recon-one`。
