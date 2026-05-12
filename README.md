# BlueTeam Log Analyzer (BLA)

<p align="center">
  <img src="docs/assets/bla-banner.png" alt="BlueTeam Log Analyzer Banner" width="760">
</p>

> 蓝队应急响应日志分析工具 | Blue Team Incident Response Log Analyzer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/Hackerchen716/blueteam-log-analyzer)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Offline](https://img.shields.io/badge/Mode-100%25%20Offline-orange)](https://github.com/Hackerchen716/blueteam-log-analyzer)

[![PyPI](https://img.shields.io/pypi/v/blueteam-log-analyzer?label=PyPI)](https://pypi.org/project/blueteam-log-analyzer/)

**BLA** 是一款面向蓝队应急响应场景的日志分析工具，支持 Windows 事件日志、Linux 认证日志、Web 访问日志等多种格式，内置 70+ 条威胁检测规则，完全离线运行，无需任何第三方服务。

---

## 功能特性

- **多格式解析**：Windows XML/EVTX、Linux auth.log/secure、Apache/Nginx 访问日志、HVV/重保 P0 结构化日志、通用文本日志（自动识别类型）
- **70+ 检测规则**：覆盖 MITRE ATT&CK 9 个阶段，包括暴力破解、密码喷洒、横向移动、权限提升、持久化、防御规避、凭据访问、Web 攻击等
- **护网/重保画像**：`--profile cn-hvv` 增强 Shiro、Fastjson、Struts2、ThinkPHP、WebLogic、Spring、Webshell 等国内常见痕迹检测
- **攻击链还原**：自动关联多文件事件，还原 ATT&CK 攻击链
- **P0 多源关联案件**：对 WAF、VPN、堡垒机、DNS、代理、防火墙、EDR、应用日志做归一化、富化和跨源关联，输出 incident 级案件视图
- **IOC 提取**：一键导出 IP、域名、URL、文件路径、Hash、账户、进程和可疑命令
- **白名单/基线压制**：支持 JSON allowlist 过滤可信 IP、账户、路径、进程、UA，并支持可信扫描器、维护窗口、规则级 suppress，降低真实环境误报
- **风险评分**：0-100 综合评分，4 级威胁分级（严重/高危/中危/低危）
- **HVV/重保采集矩阵**：内置边界、身份、终端、流量、应用、数据库、云原生、协同办公等日志源优先级，可用 `--list-log-sources` 快速查看
- **多格式输出**：终端彩色报告、独立 HTML 报告（含离线图表）、JSON、CSV、IOC 文本、**SARIF 2.1.0**（GitHub Code Scanning 兼容）
- **一键报告目录**：`--out report/` 自动生成 HTML、JSON、CSV、IOC、SARIF 五类标准产物
- **可配置阈值**：暴力破解 / DDoS / 密码喷洒等阈值集中管理，支持 `--config thresholds.json` 与 `BLA_THRESHOLD_*` 环境变量覆盖，适配不同业务环境
- **YAML 规则扩展**：支持 `--rules` 加载自定义 Web 检测规则目录，保持零依赖同时方便二次开发
- **规则质量工具**：`bla validate-rules` 校验规则元数据与正则可编译性，`bla benchmark` 评估解析/检测吞吐，`bla explain` 从 JSON 报告解释告警或案件证据
- **CI 友好**：`--exit-on {none,critical,high,medium}` 让流水线按需要的告警级别决定门禁
- **大文件友好**：Linux auth.log、Web access.log 与 P0 JSONL/key=value/CSV 日志使用逐行解析路径，多个文件可用 `-j N` 并行处理
- **完全离线**：无网络请求，无 AI 调用，所有规则内置，适合隔离网络环境
- **零依赖**：Python 3.9+ 标准库即可运行

---

## 支持的日志类型

| 日志类型 | 格式 | 说明 |
|---------|------|------|
| Windows 事件日志 | `.xml`（wevtutil 导出） | 安全/系统/应用/Sysmon 日志 |
| Windows EVTX | `.evtx`（二进制） | 需安装 `python-evtx`（可选） |
| Linux 认证日志 | `auth.log` / `secure` | SSH / Sudo / PAM / useradd |
| Web 访问日志 | Apache/Nginx Combined | SQL 注入/XSS/LFI/RCE/扫描器检测 |
| HVV/重保 P0 结构化日志 | CSV / JSONL / JSON 数组 / key=value | WAF、VPN、堡垒机、DNS、代理/NAT、防火墙、EDR、应用日志 |
| 通用文本日志 | 任意格式 | 关键字提取与告警 |

### HVV / 重保日志源采集矩阵

这份矩阵用于 HVV、重保和大型应急响应现场安排日志拉取顺序。它不是简单罗列“能拿什么日志”，而是按攻击链研判价值分成三档：

- `P0`：第一轮必采，直接支撑入口确认、账号突破、主机失陷、C2 外联、横向移动、数据访问等关键判断。
- `P1`：第二轮补全攻击链，用于交叉验证、扩大排查、确认影响面和处置闭环。
- `P2`：溯源、影响评估和运营支撑材料，用于确认资产归属、变更背景、日志缺口、备份恢复点等。

完整矩阵可直接由 CLI 输出，包含优先级、类别、类型、重要性、必备字段、研判重点和建议时间窗：

```bash
bla --list-log-sources
```

第一轮 `P0` 必采源建议优先覆盖：

| 类别 | P0 日志源 | 核心价值 |
| --- | --- | --- |
| 边界入口 | WAF / Web 安全网关日志 | 确认攻击载荷、命中规则、真实源 IP 和被打入口 |
| 边界入口 | CDN / SLB / 反向代理访问日志 | 还原真实客户端、转发链路和后端实例 |
| Web 与应用 | Web 服务器 access.log | 识别扫描、漏洞利用、Webshell 访问和批量下载 |
| Web 与应用 | 业务应用日志 | 定位鉴权绕过、反序列化、命令执行、越权和业务异常 |
| 身份与远程接入 | VPN / SSL VPN / 零信任登录日志 | 发现弱口令、撞库、异地登录和异常设备 |
| 身份与远程接入 | 堡垒机登录与命令审计 | 还原运维跳转、命令执行、文件落地和会话时间线 |
| 身份与权限 | AD / 域控 Security 日志 | 识别域账号爆破、票据滥用、横向移动、提权和权限变更 |
| 身份与权限 | IAM / SSO / MFA 审计日志 | 确认单点登录异常、MFA 绕过、云账号滥用和权限扩大 |
| 主机与终端 | EDR / XDR 告警与终端行为 | 还原木马落地、进程执行、横向移动和查杀隔离情况 |
| 主机与终端 | Windows 安全日志 / Sysmon | 追踪登录、进程、计划任务、服务安装、网络连接和持久化 |
| 主机与终端 | Linux auth.log / secure / auditd | 识别 SSH 爆破、提权、账号变更、敏感文件访问和持久化 |
| 流量与解析 | DNS 解析日志 | 发现 C2、DGA、DNS 隧道、恶意域名访问和感染主机 |
| 流量与解析 | 出口代理 / 上网行为 / SWG 日志 | 确认 C2 回连、恶意下载、数据外传和访问链路 |
| 流量与解析 | 边界防火墙 / NAT / 会话日志 | 还原南北向访问、源地址映射、出入口连接和大流量传输 |
| 流量与解析 | NDR / 天眼 / 全流量探针告警 | 发现漏洞利用、C2、横向移动、内网扫描和数据外传线索 |
| 数据与中间件 | 核心数据库审计日志 | 识别拖库、越权查询、高危 DDL/DML 和敏感表访问 |
| 云与容器 | 云平台审计日志 | 确认云账号接管、AK 滥用、权限变更和安全策略关闭 |
| 云与容器 | Kubernetes API 审计日志 | 识别 exec、Secret 读取、RBAC 变更和集群接管 |

---

## 检测规则覆盖

| 类别 | 规则示例 | MITRE ATT&CK |
|------|---------|-------------|
| 暴力破解 | SSH/RDP/Kerberos 失败登录聚合 | T1110.001 |
| 密码喷洒 | 多账户低频尝试识别 | T1110.003 |
| 横向移动 | RDP 跳转、显式凭据（PtH 指示器） | T1021.001, T1550.002 |
| 权限提升 | 添加到特权组、Sudo 滥用、Root 直接登录 | T1098.001, T1548.003 |
| 持久化 | 服务安装、计划任务创建、账户创建 | T1543.003, T1053.005, T1136 |
| 防御规避 | 日志清除（EventID 1102/104）、审计策略修改 | T1070.001, T1562.002 |
| 凭据访问 | Mimikatz 特征、LSASS 访问（Sysmon EventID 10） | T1003.001 |
| 可疑执行 | 高危 PowerShell、LOLBins（certutil/regsvr32 等） | T1059.001, T1218 |
| Web 攻击 | SQL 注入、XSS、路径遍历、命令注入、Webshell | T1190, T1059.007 |
| 侦察 | 扫描器识别（Nikto/sqlmap/nmap）、敏感文件探测 | T1595, T1083 |
| 护网画像 | Shiro/Fastjson/Struts2/ThinkPHP/WebLogic/Spring/Webshell | T1190, T1505.003 |

---

## 安装

### 环境要求

- Python 3.9 或更高版本
- 操作系统：Windows 10/11、macOS 12+、Ubuntu 20.04+（及其他主流 Linux 发行版）

### PyPI 安装（推荐）

```bash
pip install blueteam-log-analyzer
```

安装完成后可直接使用 `bla` 命令：

```bash
bla --help
bla --version
```

### 从源码运行（开发者）

macOS / Linux / Windows PowerShell：

```bash
git clone https://github.com/Hackerchen716/blueteam-log-analyzer.git
cd blueteam-log-analyzer
python3 bla_cli.py --help
```

### 可选：EVTX 二进制解析支持

```bash
pip install python-evtx
```

安装后可直接解析 `.evtx` 二进制文件，无需先用 wevtutil 转换为 XML。

---

## 使用方法

### 基本用法

```bash
# 分析单个文件（自动识别类型）
bla /var/log/auth.log

# 分析多个文件
bla /var/log/auth.log /var/log/nginx/access.log

# 分析整个目录（递归）
bla /var/log/

# 通配符（Linux/macOS）
bla /path/to/logs/*.xml
```

### 输出选项

```bash
# 生成 HTML 报告（推荐，含离线图表，浏览器打开）
bla auth.log --html report.html
open report.html          # macOS
start report.html         # Windows

# 生成 JSON 报告（便于二次处理/SIEM 导入）
bla auth.log --json report.json

# 导出 CSV（便于 Excel 分析）
bla auth.log --csv events.csv

# 导出 IOC 清单（便于封禁、研判、工单流转）
bla logs/ --ioc iocs.txt

# 同时生成所有格式
bla logs/ --html report.html --json report.json --csv events.csv --ioc iocs.txt

# 一键生成标准报告目录
bla logs/ --out incident_report/
# incident_report/
# ├── index.html
# ├── report.json
# ├── events.csv
# ├── iocs.txt
# └── report.sarif

# 生成 SARIF 报告（可上传到 GitHub Code Scanning）
bla logs/ --sarif report.sarif
gh code-scanning upload-sarif --sarif report.sarif

# 自定义阈值（公网跳板机适当调高暴力破解阈值，避免误报）
bla logs/ --config thresholds.json
# 或通过环境变量覆盖
BLA_THRESHOLD_BRUTE_FORCE_HIGH=50 bla logs/

# 并行解析多个文件
bla logs/*.evtx -j 8

# CI 流水线：只在严重以上告警时退出 1
bla logs/ --exit-on high

# 国内护网/重保增强画像
bla logs/ --profile cn-hvv --html report.html --ioc iocs.txt

# 使用白名单压制已知可信噪音
bla logs/ --allowlist docs/allowlist-example.json --html report.html

# 加载自定义 YAML 规则目录（可多次指定，也可用 BLA_RULES_DIR）
bla logs/ --rules ./my-rules --profile cn-hvv --out report/

# 校验规则元数据与正则
bla validate-rules --strict-metadata

# 对合成 P0 日志做性能基准，也可传真实日志路径
bla benchmark --size-mb 100

# 从 JSON 报告解释某个案件或告警
bla explain inc-001 --report incident_report/report.json

# 详细模式（显示所有高危以上事件）
bla auth.log --verbose

# 大型日志终端只看前 100 个告警（JSON/HTML 仍保留完整结果）
bla auth.log --max-alerts 100

# 分析历史 syslog/auth.log（日志本身不含年份时指定年份）
bla auth.log --syslog-year 2024

# 查看应急日志源采集优先级
bla --list-log-sources

# 禁用彩色输出（重定向到文件时使用）
bla auth.log --no-color > report.txt
```

### Windows 日志导出

在 Windows 主机上导出日志，拷贝到分析机后使用 BLA 分析：

```powershell
# 导出安全日志（推荐）
wevtutil epl Security Security.xml /lf:true

# 导出系统日志
wevtutil epl System System.xml /lf:true

# 导出 Sysmon 日志（需已安装 Sysmon）
wevtutil epl "Microsoft-Windows-Sysmon/Operational" Sysmon.xml /lf:true

# 导出 PowerShell 日志
wevtutil epl "Microsoft-Windows-PowerShell/Operational" PowerShell.xml /lf:true

# 分析（在任意平台）
bla Security.xml System.xml Sysmon.xml --html incident_report.html
```

### 退出码

`--exit-on` 决定何种级别的告警会触发退出码 1，默认为 `critical`。

| 退出码 | 含义 |
|--------|------|
| `0` | 分析完成，未达到 `--exit-on` 设定的告警级别 |
| `1` | 发现达到/超过 `--exit-on` 阈值的告警 |
| `130` | 用户中断（Ctrl+C） |

```bash
bla logs/ --exit-on none           # 永远 exit 0，仅生成报告
bla logs/ --exit-on medium         # 任何中危以上告警都触发 exit 1
```

退出码可用于自动化告警脚本：

```bash
bla /var/log/auth.log --json /tmp/result.json
if [ $? -eq 1 ]; then
    echo "发现严重威胁！" | mail -s "BLA Alert" security@example.com
fi
```

---

## 终端报告示例

关键事件时间线、ATT&CK 技术映射、应急处置建议、Top 攻击源 IP：

![BLA 终端报告示例](docs/screenshots/demo.png)

---

## 真实样本实测

已使用 SecRepo 公开日志完成实测，覆盖 Linux auth.log 和 Web access.log 两类场景：

| 样本 | 原始行数 | 解析事件 | 告警 | 风险 | 主要验证能力 |
|------|----------|----------|------|------|--------------|
| SecRepo auth.log | 86,839 | 27,075 | 624 | 100/100（严重） | SSH 暴力破解、密码喷洒、Top IP/Top User、IOC 提取 |
| SecRepo Web access.log | 2,928 | 236 | 2 | 100/100（严重） | 敏感路径探测、Web 访问日志解析、`cn-hvv` 画像、IOC 提取 |

完整复现命令、数据来源和结果摘要见 [SecRepo 真实样本实测记录](docs/secrepo-demo.md)。

### SecRepo auth.log 实测总览

![SecRepo auth.log 实测总览](docs/screenshots/secrepo-auth-overview.png)

### 暴力破解告警详情

![SecRepo auth.log 暴力破解告警详情](docs/screenshots/secrepo-auth-alerts.png)

### Top 攻击源 IP 与报告输出

![SecRepo auth.log Top 攻击源 IP 与报告输出](docs/screenshots/secrepo-auth-top-ip.png)

---

## 输出示例

### 终端报告

```
╔══════════════════════════════════════════════════════════════════════════════╗
║         BlueTeam Log Analyzer (BLA)  -  Blue Team Incident Response          ║
║                    Version 1.1.0  |  100% Offline  |  No AI                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 分析总览
  综合风险评分: 87/100  [高危]
  分析文件数:   3
  总事件数:     1,247
  告警数量:     12

⛓ ATT&CK 攻击链分析
  ▶ 侦察 (13 事件) → ▶ 初始访问 (3 事件) → ▶ 执行 (4 事件)
  → ▶ 持久化 (2 事件) → ▶ 权限提升 (2 事件) → ▶ 凭据访问 (29 事件)

🚨 威胁告警
  [01] [严重] Web攻击: 命令注入/代码执行
  [02] [高危] 暴力破解攻击 (192.168.1.100, 失败 50 次)
  [03] [高危] 密码喷洒攻击 (针对 17 个账户)
  ...

💡 应急处置建议
  1. 【紧急】封锁攻击源 IP 192.168.1.100
  2. 【高危】审查 root 账户直接登录记录
  ...
```

### HTML 报告功能

- 风险评分仪表盘
- 事件级别分布图（纯 HTML/CSS，无需联网）
- Top 攻击源 IP 柱状图（纯 HTML/CSS，无需联网）
- ATT&CK 攻击链可视化
- IOC 摘要（IP、域名、URL、路径、Hash、账户、进程、命令）
- 告警过滤（按级别/关键词搜索）
- 关键事件时间线（支持滚动）
- 应急处置建议

---

## 开发与测试

```bash
# 语法检查
python3 -m compileall -q bla bla_cli.py setup.py tests

# 回归测试（仅使用 Python 标准库）
python3 -m unittest discover -s tests -v
```

当前回归测试覆盖：

- HTML 报告对日志内容做转义，避免攻击日志触发报告 XSS
- HTML 报告不依赖外部 CDN，保持离线可用
- Web payload 中带空格或 URL 编码时仍可识别 SQL 注入 / XSS
- 高频 200 请求可生成扫描/洪泛类告警
- Windows XML 异常字段不会导致整条事件被静默丢弃
- IOC 提取与 `--ioc` 文本导出
- `--profile cn-hvv` 国内护网/重保增强画像
- `--allowlist` 白名单误报压制
- 大型日志可通过 `--max-alerts` 控制终端告警展示数量
- 可通过 `--syslog-year` 固定 Linux syslog 无年份时间戳
- `--out` 标准报告目录可一次生成 HTML/JSON/CSV/IOC/SARIF
- 内置 YAML Web 规则与 `--rules` 自定义规则加载
- 自动识别 Linux/Web 日志时可走逐行解析路径，避免大文件一次性读入内存

更多可用于评估 BLA 的公开日志与靶场资源见 [测试资源推荐清单](docs/testing-resources.md)。
SecRepo 真实样本的完整复现实测见 [SecRepo 真实样本实测记录](docs/secrepo-demo.md)。

---

## 自定义规则

BLA 支持加载简单 YAML Web 检测规则。规则文件可放在任意目录中，通过 `--rules` 指定；每个 `.yaml` / `.yml` 文件可包含一个 `web_attacks` 列表。

```yaml
web_attacks:
  - id: WEB-CUSTOM-001
    name: 自定义漏洞探测
    level: high
    category: Web攻击
    mitre: T1190
    tags: [custom, exploit, web-attack]
    patterns:
      - '/custom-vuln-probe'
      - 'custom_payload='
```

运行：

```bash
bla access.log --rules ./rules --out report/
```

内置 Web YAML 规则位于 `bla/rules/web_attacks.yaml`，当前包含 Log4Shell/JNDI、Nacos、Swagger/OpenAPI 暴露等规则。未安装 PyYAML 时，BLA 会使用内置的轻量 YAML 子集解析器；如需更完整的 YAML 语法，可自行安装 PyYAML。

---

## 项目结构

```
blueteam-log-analyzer/
├── bla_cli.py              # CLI 主入口
├── bla/
│   ├── models.py           # 数据模型（LogEvent, DetectionAlert, AnalysisSummary 等）
│   ├── config.py           # 阈值配置中心（支持环境变量 / JSON 覆盖）
│   ├── allowlist.py        # 白名单过滤
│   ├── ioc.py              # IOC 提取（支持基于告警的高置信度模式）
│   ├── rules/
│   │   ├── loader.py       # YAML 规则加载器（PyYAML 可选，内置轻量解析器）
│   │   └── web_attacks.yaml# 内置 Web 扩展规则
│   ├── parsers/
│   │   ├── __init__.py     # 自动类型识别路由
│   │   ├── windows_evtx.py # Windows 事件日志解析（XML/EVTX）
│   │   ├── linux_auth.py   # Linux 认证日志解析（带跨年处理）
│   │   ├── web_access.py   # Web 访问日志解析（基于分钟桶的 DDoS 检测）
│   │   └── stats.py        # 统计计算（Top IP、Top User、时间范围等）
│   ├── detection/
│   │   └── engine.py       # 威胁检测引擎（统一规则源；私网 IP 自动降级）
│   ├── output/
│   │   ├── terminal.py     # 终端彩色输出（ANSI，支持 Windows 10+）
│   │   ├── html_report.py  # HTML 报告生成（独立单文件）
│   │   ├── json_report.py  # JSON 报告输出
│   │   ├── csv_report.py   # CSV 事件导出
│   │   ├── ioc_report.py   # IOC 清单导出
│   │   ├── sarif_report.py # SARIF 2.1.0 输出（接入 GitHub Code Scanning 等）
│   │   └── bundle.py       # --out 标准报告目录生成
│   └── utils/
│       └── helpers.py      # 工具函数
├── docs/
│   ├── screenshots/        # 界面截图
│   ├── allowlist-example.json # 白名单示例
│   ├── secrepo-demo.md     # SecRepo 真实样本实测记录
│   └── testing-resources.md# 测试资源推荐清单
├── sample_logs/
│   ├── auth.log            # Linux SSH 暴力破解示例日志
│   └── access.log          # Web 攻击示例日志（SQLi/XSS/LFI/扫描）
├── tests/
│   └── test_regressions.py # 安全与解析回归测试
├── setup.py                # Python 包安装配置
└── README.md
```

---

## 参与贡献

欢迎提交 Issue / Pull Request，一起完善 BLA 在蓝队日志分析、护网、重保值守和应急响应场景下的实用能力。

当前需要的优化方向：

- **日志解析**：补充更多常见安全设备、主机、Web 服务与业务日志格式。
- **检测规则**：完善 Web 攻击、爆破、横向移动、权限变更、可疑执行、日志清除等蓝队常见场景。
- **误报压制**：改进 allowlist、基线、可信扫描器、维护窗口等机制。
- **报告输出**：优化 HTML / JSON / CSV / IOC / SARIF 报告，让结果更适合值守、复盘和工单流转。
- **样本与测试**：补充脱敏样本、单元测试、回归测试和性能测试。
- **易用性与部署**：改进安装体验、文档、Docker 镜像、本地 Web UI 等。

请不要提交真实客户日志、敏感 IP、账号、Cookie、Token、业务数据或未脱敏截图。

交流与合作：`hackerchen7@proton.me`

---

## 许可证

[MIT License](LICENSE) © 2026 Hackerchen716
