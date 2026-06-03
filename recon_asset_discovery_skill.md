# Recon-Asset-Discovery-Skill：授权目标信息搜集与资产归因 Skill

> 适用场景：EDUsrc、SRC、企业授权测试、红队前期侦察、校园网络安全训练营、安全资产梳理、漏洞入口发现。  
> 使用前提：仅限合法授权范围内的信息搜集、资产梳理和安全测试准备。不得用于未授权攻击、撞库、口令爆破、绕过访问控制、破坏业务或数据窃取。

---

## 1. Skill 基本信息

```yaml
skill_name: Recon-Asset-Discovery-Skill
version: 1.0.0
language: zh-CN
category: cybersecurity_reconnaissance
scenario:
  - EDUsrc
  - SRC
  - authorized_security_testing
  - red_team_preparation
  - campus_network_security_training
  - attack_surface_management
risk_level: controlled_dual_use
execution_mode:
  - passive_first
  - low_rate_active_recon
  - manual_verification_required
```

---

## 2. Skill 定位

该 Skill 用于在合法授权范围内，对目标组织进行公开信息搜集、资产扩展、资产归因、子域名发现、端口识别、Web 存活探测、URL 爬取、路径参数提取、JavaScript 分析和高价值入口筛选。

核心目标不是“跑工具”，而是建立一条稳定的信息搜集链路：

```text
目标边界确认
    ↓
公开信息搜集
    ↓
资产扩展与归因
    ↓
子域名与 IP 发现
    ↓
存活探测与技术识别
    ↓
URL / JS / 历史接口搜集
    ↓
路径与参数字典生成
    ↓
低速目录与参数发现
    ↓
威胁建模与高价值入口筛选
    ↓
输出信息搜集报告
```

---

## 3. 适用边界与安全约束

### 3.1 必须满足

```yaml
requirements:
  - 必须明确授权范围
  - 必须记录目标来源
  - 必须区分 confirmed / suspected / third_party / out_of_scope
  - 必须先被动搜集，再低速主动探测
  - 必须避免影响业务可用性
  - 必须对 EDU、政府、医疗、金融等目标降低扫描频率
```

### 3.2 禁止行为

```yaml
forbidden:
  - 未授权资产扫描
  - 登录爆破
  - 撞库
  - 使用泄露凭据登录系统
  - 利用漏洞获取数据
  - 执行破坏性 Payload
  - 绕过访问控制
  - 对生产系统进行高并发目录爆破
  - 对不确定归属资产进行主动攻击测试
```

### 3.3 资产归属标签

```yaml
asset_ownership_tags:
  confirmed: 已确认属于授权范围
  suspected: 疑似相关，需要人工确认
  third_party: 第三方供应商或 SaaS 服务
  out_of_scope: 明确不在授权范围
```

只有 `confirmed` 和经过人工确认的 `suspected` 资产可进入主动探测阶段。

---

## 4. Skill 输入

```yaml
input_schema:
  target_name:
    type: string
    description: 目标组织名称，例如 南京信息工程大学
  root_domains:
    type: array
    example:
      - example.edu.cn
      - example.com
  scope:
    type: array
    description: 明确授权范围
    example:
      - "*.example.edu.cn"
      - "192.0.2.0/24"
  out_of_scope:
    type: array
    description: 明确禁止测试的资产
    example:
      - "payment.example.edu.cn"
      - "thirdparty.example.com"
  scan_policy:
    type: object
    properties:
      passive_only: false
      max_threads: 20
      request_delay: "0.5s"
      allow_port_scan: true
      allow_directory_fuzz: true
      allow_js_analysis: true
  output_dir:
    type: string
    example: "./recon_output"
```

---

## 5. Skill 输出

```yaml
output_files:
  domains.txt: 主域名与关联根域名
  subs.txt: 子域名全集
  subs_live.txt: 存活 Web 资产
  ips.txt: IP 与网段资产
  ports.txt: 开放端口与服务
  urls.txt: URL 资产
  js.txt: JavaScript 文件
  paths.txt: 自定义路径字典
  params.txt: 自定义参数字典
  tech_stack.csv: 技术栈识别结果
  screenshots/: 站点截图
  github_leaks.csv: GitHub 线索
  high_value.txt: 高价值测试入口
  asset_score.csv: 资产评分表
  recon_report.md: 信息搜集报告
```

---

## 6. 总体执行原则

```text
1. 先确认授权范围，再进行任何主动探测。
2. 先被动搜集，再主动探测。
3. 先清洗数据，再交给扫描器。
4. 先低速、小样本验证，再扩大范围。
5. 先识别资产归属，再判断是否进入测试。
6. 先截图和人工筛选，再决定高价值目标。
7. 路径字典、参数字典必须从目标自身数据中持续迭代。
8. 工具结果只能作为线索，不能直接作为漏洞结论。
```

---

# 7. 执行流程

---

## Phase 0：初始化任务

### 目标

创建输出目录、记录授权范围、初始化资产状态表。

### 输入

```text
target_name
root_domains
scope
out_of_scope
scan_policy
```

### 输出

```text
scope.md
asset_inventory.csv
```

### Agent 动作

```text
1. 读取目标名称、主域名、授权范围。
2. 如果授权范围缺失，停止主动探测，仅允许公开信息整理。
3. 创建输出目录。
4. 初始化资产清单字段。
```

### asset_inventory.csv 字段

```csv
asset,type,source,ownership,status_code,title,tech,ip,port,tags,score,note
```

---

## Phase 1：目标边界与资产归因

### 目标

明确哪些资产属于目标，哪些只是疑似或第三方。

### 方法

```text
1. 官网底部、关于我们、信息公开页面
2. Whois / 反向 Whois
3. 证书 CN / SAN
4. 备案信息
5. 搜索引擎结果
6. Shodan / Netlas / Censys
7. 组织名关联
8. 学校、企业、集团下属单位信息
```

### 输出标签

```yaml
ownership_score:
  100: 授权范围明确包含
  90: 官网直接引用
  80: 证书组织名明确一致
  70: Whois / 备案相关
  60: 搜索引擎疑似相关
  50: 供应商或第三方
  0: 明确不在范围
```

### 判断规则

```text
score >= 80：可进入低速主动探测
60 <= score < 80：需要人工确认
score < 60：不进入主动探测
```

---

## Phase 2：公开文档与默认信息搜集

### 目标

从公开搜索结果中寻找系统入口、操作手册、默认密码规则、平台说明、接口文档、系统名称。

### EDU 常用搜索语法

```text
site:目标域名 intext:操作手册|使用手册|操作视频|使用视频|演示视频|白皮书
site:目标域名 intext:管理|后台|登录|用户名|密码|系统|账号|手册
site:目标域名 "默认密码"
site:目标域名 "学号"
site:目标域名 "工号"
site:目标域名 "账号" "密码"
site:目标域名 filetype:pdf
site:目标域名 filetype:doc
site:目标域名 filetype:xls
site:目标域名 filetype:xlsx
```

### 公开手册价值分级

```yaml
document_value_level:
  P1: 包含系统地址 + 默认账号或默认密码规则
  P2: 包含系统地址 + 操作流程
  P3: 只包含系统名称或截图
  P4: 过期文档、历史通知、无入口
```

### 输出

```text
docs_found.csv
manual_keywords.txt
system_names.txt
possible_default_rules.txt
```

### 注意

```text
默认密码规则只能作为风险线索，不允许直接用于未授权登录尝试。
```

---

## Phase 3：搜索引擎 Dork 搜集

### 目标

发现登录入口、后台、API 文档、敏感文件、参数型 URL、文件上传点、暴露配置。

### 通用 Dork 模板

```text
site:目标域名 inurl:login
site:目标域名 inurl:admin
site:目标域名 inurl:manage
site:目标域名 inurl:manager
site:目标域名 inurl:system
site:目标域名 inurl:api
site:目标域名 inurl:swagger
site:目标域名 inurl:api-docs
site:目标域名 inurl:upload
site:目标域名 "choose file"
site:目标域名 ext:log
site:目标域名 ext:env
site:目标域名 ext:bak
site:目标域名 ext:sql
site:目标域名 ext:conf
site:目标域名 ext:ini
```

### 漏洞倾向参数 Dork

```text
XSS 倾向:
site:目标域名 inurl:q=|inurl:s=|inurl:search=|inurl:query=|inurl:keyword=

重定向倾向:
site:目标域名 inurl:url=|inurl:return=|inurl:next=|inurl:redirect=|inurl:redir=

SQL 注入倾向:
site:目标域名 inurl:id=|inurl:pid=|inurl:category=|inurl:cat=|inurl:action=

SSRF 倾向:
site:目标域名 inurl:url=|inurl:path=|inurl:dest=|inurl:html=|inurl:data=

LFI 倾向:
site:目标域名 inurl:file=|inurl:folder=|inurl:include=|inurl:dir=

RCE 倾向:
site:目标域名 inurl:cmd=|inurl:exec=|inurl:run=|inurl:ping=
```

### FOFA / 空间搜索引擎思路

```text
domain="目标域名"
host="目标域名"
cert="目标组织名"
org="目标组织名"
icon_hash="favicon_hash"
title="后台"
title="管理"
body="目标组织名"
```

### 输出字段

```csv
url,title,source,dork,status_code,content_length,risk_tag,note
```

---

## Phase 4：GitHub 信息泄露搜集

### 目标

发现目标域名、接口、配置文件、测试环境地址、Token 字段、AK/SK 字段、数据库连接信息线索。

### 手动搜索语法

```text
"目标域名"
"目标域名" password
"目标域名" token
"目标域名" secret
"目标域名" api_key
"目标域名" access_key
"目标域名" private_key
"目标域名" jdbc
"目标域名" mysql
"目标域名" redis
"目标域名" oss
"目标域名" smtp
```

### GitHub 高级语法

```text
in:name 目标关键词
in:description 目标关键词
in:readme 目标关键词
language:java 目标域名
language:php 目标域名
language:python 目标域名
language:javascript 目标域名
pushed:>2024-01-01 目标域名
created:>2024-01-01 目标域名
```

### 自动化工具

```text
GitDorker
trufflehog
gitleaks
```

### 输出

```csv
repo,file,url,keyword,matched_type,pushed_at,confidence,note
```

### 处理规则

```text
1. 优先查看最近一年更新的仓库。
2. 区分原始仓库与 Fork 仓库。
3. 发现疑似密钥仅做风险记录，不进行越权验证。
4. 所有敏感字段脱敏写入报告。
```

---

## Phase 5：ASN、证书、IP 与组织资产扩展

### 目标

从组织名、ASN、证书、Shodan、Netlas、Censys 等扩展资产。

### 典型方法

```text
ASN → IP 段 → IP 列表 → 端口扫描
证书 CN / SAN → 子域名
组织名 → 关联证书
反向 Whois → 关联域名
Shodan / Netlas / Censys → 暴露服务
```

### 命令示例

```bash
cat ipscope.txt | mapcidr | tee ips.txt
```

```bash
subfinder -d example.edu.cn -all | tee subfinder.txt
amass enum --passive -d example.edu.cn | tee amass.txt
cat subfinder.txt amass.txt | sort -u | tee subs.txt
```

### 注意

```text
ASN 和 IP 段很容易扩大到非授权范围。只有确认属于授权范围的 IP 才能进入主动扫描。
```

---

## Phase 6：子域名被动搜集与主动爆破

### 被动搜集

```bash
subfinder -d example.edu.cn -all -o subfinder.txt
amass enum --passive -d example.edu.cn -o amass.txt
cat subfinder.txt amass.txt | sort -u | tee subs_passive.txt
```

### 主动爆破

```bash
puredns bruteforce all.txt example.edu.cn -r resolvers.txt | sort -u | tee puredns.txt
```

### 规则生成

```bash
cat subs_passive.txt | dnsgen - | puredns resolve --resolvers resolvers.txt | tee dnsgen_resolved.txt
```

### 合并去重

```bash
cat subs_passive.txt puredns.txt dnsgen_resolved.txt | sort -u | tee subs.txt
```

### 常见问题

```text
1. DNS 解析器质量差导致误报
2. 泛解析导致大量脏数据
3. 字典过大导致效率低
4. 结果没有和存活探测联动
```

---

## Phase 7：Web 存活探测与技术栈识别

### 命令

```bash
httpx -l subs.txt -title -tech-detect -status-code -follow-redirects -o subs_live.txt
```

### 输出字段

```csv
url,status_code,title,content_length,tech,webserver,ip,cname
```

### 高价值标题关键词

```text
后台
管理
登录
统一身份认证
Swagger
ApiDoc
Jenkins
Grafana
RabbitMQ
phpMyAdmin
Spring Boot
Actuator
接口文档
测试
Dev
UAT
Staging
```

---

## Phase 8：端口扫描与服务识别

### 推荐低速流程

```bash
naabu -l targets.txt -top-ports 1000 -rate 1000 -silent -o ports.txt
nmap -sV -iL ports.txt -oN nmap_services.txt
```

### 高价值端口

```text
80,443,8080,8443,8000,8888,9000,7001,7002,5000,3000,6379,9200,5601,15672,27017,3306,5432,22,3389
```

### 注意

```text
1. EDU 目标降低速率。
2. 不对不确定归属 IP 扫描。
3. 先常见端口，再全端口。
4. 避免业务高峰。
```

---

## Phase 9：Favicon 与技术指纹关联

### 目标

通过 Favicon Hash、Wappalyzer、WhatWeb、httpx 技术识别寻找同技术或同系统资产。

### 方法

```bash
cat urls.txt | python3 favfreak.py
```

FOFA 示例：

```text
icon_hash="xxxxxx"
```

### 判断原则

```text
Favicon 只能作为关联线索，不能单独证明资产归属。
```

---

## Phase 10：截图与人工筛选

### Gowitness

```bash
gowitness file -f urls.txt --threads 50
gowitness report serve -a 0.0.0.0:7171
```

### 筛选目标

```text
登录后台
管理系统
测试系统
API 文档
报错页面
默认页面
403 页面
老旧系统
运维组件
```

### 输出

```text
screenshots/
screenshot_index.html
visual_high_value.txt
```

---

## Phase 11：URL 爬虫与历史 URL 搜集

### 工具组合

```bash
cat subs_live.txt | katana -sc -kf robotstxt,sitemapxml -jc -c 50 -o katana.txt
cat subs_live.txt | hakrawler -subs > hakrawler.txt
gospider -S subs_live.txt -o gospider_output -c 50 -d 2 --other-source --subs --sitemap --robots
cat domains.txt | gau > gau.txt
cat domains.txt | waybackurls > wayback.txt
```

### 合并

```bash
cat katana.txt hakrawler.txt gau.txt wayback.txt | sort -u | tee urls.txt
```

### 高价值 URL 过滤

```bash
grep -Ei "redirect=|url=|return=|next=|callback=|file=|path=|id=|uid=|token=|key=|api|upload|download" urls.txt | tee high_value_urls.txt
```

### 工具特性

```yaml
Burp:
  advantage: 手工业务流发现强
  weakness: 自动化弱
Katana:
  advantage: JS 解析、sitemap、robots 支持较好
  weakness: 需要清洗
Gospider:
  advantage: 其他数据源和历史源较多
  weakness: 脏数据多
Gau:
  advantage: 快速获取历史 URL
  weakness: 需要强清洗
Hakrawler:
  advantage: 轻量
  weakness: 效果不稳定
Oxdork:
  advantage: 搜索引擎补充能力强
  weakness: 依赖搜索结果质量
```

---

## Phase 12：路径字典与参数字典生成

### 路径字典

```bash
cat urls.txt | unfurl paths | sed 's/^.//' | sort -u | egrep -iv "\.(jpg|jpeg|gif|png|css|js|svg|ico|pdf|woff|woff2|ttf|mp4|mp3|zip|rar)$" | tee paths.txt
```

### 参数字典

```bash
cat urls.txt | unfurl keys | sort -u | tee params.txt
```

### 原则

```text
同一组织不同子域之间经常复用路径和参数，因此目标专属字典比通用字典更有价值。
```

---

## Phase 13：目录发现与参数发现

### 目录发现

```bash
feroxbuster --url https://example.edu.cn/ -w paths.txt --rate-limit 20
dirsearch -u https://example.edu.cn/ -i 200,403
ffuf -w paths.txt -u https://example.edu.cn/FUZZ -mc all
```

### 参数发现

```text
Burp GAP
Param-Miner
Arjun
Burp Intruder
```

### 低速策略

```yaml
directory_fuzz_policy:
  max_threads: 10
  request_delay: "0.5s"
  retry: false
  follow_redirect: false
  filter_static_404: true
  stop_on_waf_block: true
```

### 注意

```text
目录爆破不应对全量资产无脑执行。优先选择登录系统、API 系统、测试环境、老旧系统、文件上传系统、非标准端口 Web 服务。
```

---

## Phase 14：JavaScript 分析与接口监控

### JS 提取

```bash
grep -Ei "\.js($|\?)" urls.txt | sort -u | tee js.txt
```

### 分析目标

```text
API 接口
测试环境地址
上传接口
下载接口
管理端路径
隐藏参数
版本号
第三方服务地址
Token 字段名
AccessKey 字段名
```

### 工具

```text
JSSCAN
LinkFinder
SecretFinder
JSMon
自定义正则
```

### 监控策略

```text
1. 周期性拉取 JS 文件。
2. 计算文件 hash。
3. 检测新增接口。
4. 新增接口进入 high_value_urls.txt。
```

---

## Phase 15：威胁建模与高价值资产筛选

### 目标

从大量资产中找出最值得人工验证的入口。

### 高价值资产关键词

```text
admin
login
manage
manager
system
api
swagger
upload
download
dev
test
uat
staging
internal
debug
console
actuator
jenkins
grafana
rabbitmq
nacos
druid
xxl-job
```

### 快速过滤

```bash
grep -Ei "admin|login|manage|system|api|swagger|upload|dev|test|uat|staging|internal|debug|console|actuator|jenkins|grafana|rabbitmq|nacos|druid|xxl-job" urls.txt | tee high_value.txt
```

### 评分规则

```yaml
score_rules:
  api_doc:
    keyword: ["swagger", "api-docs", "apidoc"]
    score: 95
  login_panel:
    keyword: ["login", "统一身份认证", "后台"]
    score: 85
  file_upload:
    keyword: ["upload", "choose file"]
    score: 90
  test_env:
    keyword: ["dev", "test", "uat", "staging"]
    score: 90
  ops_component:
    keyword: ["jenkins", "grafana", "rabbitmq", "nacos", "druid", "actuator"]
    score: 95
  redirect_param:
    keyword: ["redirect=", "url=", "return=", "next="]
    score: 80
  sensitive_file:
    keyword: [".env", ".bak", ".sql", ".log", ".conf"]
    score: 90
```

### 优先级

```text
API 文档 > 运维组件 > 文件上传 > 测试环境 > 登录后台 > 非标准端口 > 普通门户
```

---

# 8. 最终报告模板

## recon_report.md

```markdown
# 信息搜集报告

## 1. 基本信息

- 目标名称：
- 主域名：
- 授权范围：
- 搜集时间：
- 执行人员：
- 扫描策略：

## 2. 资产概览

| 类型 | 数量 |
|---|---:|
| 主域名 | |
| 子域名 | |
| 存活 Web | |
| IP | |
| 开放端口 | |
| URL | |
| JS 文件 | |
| 高价值入口 | |

## 3. 资产归属说明

| 资产 | 来源 | 归属标签 | 置信度 | 说明 |
|---|---|---|---:|---|

## 4. 公开文档与默认信息线索

| 文档 URL | 类型 | 价值等级 | 发现内容 | 备注 |
|---|---|---|---|---|

## 5. GitHub 泄露线索

| 仓库 | 文件 | 命中关键词 | 风险类型 | 置信度 | 备注 |
|---|---|---|---|---:|---|

## 6. 子域名与 Web 资产

| URL | 状态码 | 标题 | 技术栈 | 标签 | 分数 |
|---|---:|---|---|---|---:|

## 7. 端口与服务

| IP/Host | 端口 | 服务 | 版本 | 风险备注 |
|---|---:|---|---|---|

## 8. 高价值入口

| URL | 类型 | 原因 | 优先级 | 建议 |
|---|---|---|---|---|

## 9. 信息搜集结论

- 资产规模：
- 重点系统：
- 重点风险方向：
- 后续建议：

## 10. 限制与说明

- 本报告仅基于授权范围内的信息搜集。
- 未对未确认归属资产进行主动测试。
- 默认账号、疑似密钥、敏感路径仅作为风险线索记录。
```

---

# 9. Agent 执行伪代码

```python
def recon_asset_discovery_skill(task):
    validate_scope(task.scope)

    init_output(task.output_dir)

    domains = collect_root_domains(task.root_domains, task.target_name)
    ownership = verify_asset_ownership(domains, task.scope)

    public_docs = search_public_documents(domains)
    dork_results = run_search_engine_dorks(domains)
    github_results = search_github_leaks(domains, task.target_name)

    cert_assets = collect_certificate_assets(domains, task.target_name)
    passive_subs = collect_passive_subdomains(domains)
    brute_subs = brute_subdomains(domains, policy=task.scan_policy)

    subs = merge_and_deduplicate([passive_subs, brute_subs, cert_assets])
    confirmed_subs = filter_by_scope_and_ownership(subs, ownership)

    live_assets = probe_http(confirmed_subs, policy=task.scan_policy)
    tech_results = detect_technology(live_assets)

    if task.scan_policy.allow_port_scan:
        ports = scan_ports(confirmed_subs, policy=task.scan_policy)

    screenshots = take_screenshots(live_assets)

    urls = crawl_urls(live_assets, policy=task.scan_policy)
    historical_urls = collect_historical_urls(domains)
    all_urls = merge_and_deduplicate([urls, historical_urls, dork_results.urls])

    js_files = extract_js_files(all_urls)
    js_findings = analyze_javascript(js_files)

    paths = generate_path_dictionary(all_urls)
    params = generate_param_dictionary(all_urls)

    if task.scan_policy.allow_directory_fuzz:
        directory_findings = low_rate_directory_discovery(live_assets, paths)

    high_value_assets = score_assets(
        live_assets=live_assets,
        urls=all_urls,
        js_findings=js_findings,
        github_results=github_results,
        directory_findings=directory_findings
    )

    generate_report(
        domains=domains,
        ownership=ownership,
        public_docs=public_docs,
        github_results=github_results,
        live_assets=live_assets,
        tech_results=tech_results,
        urls=all_urls,
        js_findings=js_findings,
        high_value_assets=high_value_assets
    )

    return {
        "status": "completed",
        "output_dir": task.output_dir,
        "high_value_count": len(high_value_assets)
    }
```

---

# 10. 可导入智能体的系统提示词版本

```text
你是一个授权目标信息搜集与资产归因智能体，任务是在合法授权范围内完成目标组织的信息搜集、资产扩展、存活探测、URL 爬取、路径参数提取、JavaScript 分析和高价值入口筛选。

你的执行原则：

1. 必须先确认授权范围。授权范围缺失时，只允许被动公开信息整理，不允许主动扫描。
2. 必须区分 confirmed、suspected、third_party、out_of_scope 四类资产。
3. 只有 confirmed 和人工确认后的 suspected 资产可以进入主动探测。
4. 必须先被动搜集，再低速主动探测。
5. 不允许登录爆破、撞库、使用泄露凭据、越权访问、漏洞利用、数据读取或破坏性测试。
6. 任何疑似敏感信息只作为风险线索记录，并进行脱敏。
7. 对 EDU、政府、医疗、金融等目标必须降低扫描频率。
8. 工具输出必须去重、清洗、分类、打标签、评分。
9. 最终输出 domains.txt、subs.txt、subs_live.txt、ips.txt、ports.txt、urls.txt、js.txt、paths.txt、params.txt、tech_stack.csv、screenshots/、high_value.txt、recon_report.md。
10. 信息搜集的最终目标是通过威胁建模筛选高价值入口，而不是无差别扩大扫描范围。

你的工作流：

- Phase 0：初始化任务与授权范围确认
- Phase 1：目标边界与资产归因
- Phase 2：公开文档与默认信息搜集
- Phase 3：搜索引擎 Dork 搜集
- Phase 4：GitHub 信息泄露搜集
- Phase 5：ASN、证书、IP 与组织资产扩展
- Phase 6：子域名被动搜集与主动爆破
- Phase 7：Web 存活探测与技术栈识别
- Phase 8：端口扫描与服务识别
- Phase 9：Favicon 与技术指纹关联
- Phase 10：截图与人工筛选
- Phase 11：URL 爬虫与历史 URL 搜集
- Phase 12：路径字典与参数字典生成
- Phase 13：目录发现与参数发现
- Phase 14：JavaScript 分析与接口监控
- Phase 15：威胁建模与高价值资产筛选
- Phase 16：输出信息搜集报告

当用户给出目标后，你应先询问或确认授权范围；若用户已提供授权范围，则开始生成执行计划和命令清单。所有命令应默认使用低速、低线程、可中断策略。任何可能造成业务压力的步骤都必须标记为“需要用户确认后执行”。
```

---

# 
