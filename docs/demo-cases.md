# BLA 演示案例库与功能覆盖报告

更新时间：2026-05-31

状态：随仓库维护的案例说明；涉及远程目标的步骤仅作为授权环境模板。

这份报告的目标不是再做一组静态展示图，而是把 BlueTeam Log Analyzer (BLA) 可以讲清楚、跑得通、可复查的演示案例整理成一套案例库。案例分成三类：

- **已随仓库本地复现**：使用 `sample_logs/` 和 `tests/fixtures/` 内的小样本，适合现场快速演示、CI 回归和截图。
- **已实测公开样本**：使用 SecRepo 公开日志完成过实际运行，结果已记录在 `docs/secrepo-sample-validation.md`。
- **公开真实数据源候选**：来源已核对，适合覆盖更多攻击链、Windows EVTX、多源 SOC 数据和大文件性能，但发布包不内置这些数据，避免体积、授权和敏感内容问题。

## 结论摘要

BLA 目前最适合展示的主线是：

1. 从 Linux auth.log 或 Web access.log 进入，证明解析、暴力破解、Web 攻击、IOC 和 ATT&CK 时间线不是空壳。
2. 用 Windows XML/EVTX 样本展示 RDP 登录专项、进程创建和 Windows 事件兼容边界。
3. 用 HVV/重保 P0 多源链路样本展示 WAF、应用、EDR、DNS、代理、防火墙如何合成一个 Incident。
4. 用 `--out` 证明 BLA 不只是终端输出，还能交付 HTML、JSON、研判 Markdown、CSV、IOC、SARIF 和 manifest。
5. 用 `validate-rules`、`--allowlist`、`benchmark`、`remote-log --help` 证明它具备规则治理、误报压制、性能基准和远程只读采集入口。

如需做对外演示，建议准备一个明确授权的真实远程 SSH 目标；`remote-log` 的 help 和单元测试已覆盖接口，本文件只记录可复现路径和授权环境模板。

## 功能覆盖矩阵

| BLA 功能 | 推荐演示案例 | 本地可复现材料 | 公开真实数据源 | 覆盖状态 |
| --- | --- | --- | --- | --- |
| Linux auth.log 解析 | SSH 暴力破解、密码喷洒、root 登录、新增后门账户 | `sample_logs/auth.log` | SecRepo `auth.log.gz`、Loghub OpenSSH | 已本地复现；SecRepo 已实测 |
| Web access.log 解析 | 敏感路径探测、扫描器、SQLi/XSS/LFI/RCE 规则 | 现有规则与 SecRepo 记录 | SecRepo `self.logs`、Loghub Apache | SecRepo 已实测 |
| Windows XML | RDP 4624/4625、4688 进程创建 | `sample_logs/windows_rdp_sample.xml`、`sample_logs/windows_4688_sample.xml` | EVTX-ATTACK-SAMPLES、Mordor/Security-Datasets | 已本地复现 XML；EVTX 候选 |
| Windows EVTX | 原始 `.evtx` 攻击样本解析 | 需安装 `blueteam-log-analyzer[evtx]` | EVTX-ATTACK-SAMPLES、hayabusa sample EVTX | 候选；发布包不内置 |
| RDP 专项 | 仅保留带远程来源的 Windows 登录事件 | `--rdp` + `windows_rdp_sample.xml` | EVTX-ATTACK-SAMPLES Lateral Movement | 已本地复现 |
| HVV/重保 P0 | WAF + 应用 + EDR + DNS + 代理 + 防火墙串联 | `tests/fixtures/p0/hvv_chain.jsonl` | Splunk BOTS、Mordor、安全设备导出 | 已本地复现 |
| Incident 关联 | 同源 IP/主机/域名/账号聚合案件 | `hvv_chain.jsonl`、`auth.log` | BOTS、Mordor、CyberDefenders | 已本地复现 |
| ATT&CK 时间线 | 初始访问、凭据访问、持久化、命令控制、外传 | `auth.log`、`hvv_chain.jsonl` | EVTX-ATTACK-SAMPLES、Mordor | 已本地复现 |
| IOC 提取 | IP、域名、URL、账号、进程、命令、路径 | `--out` 输出 `iocs.txt` | SecRepo、BOTS、Mordor | 已本地复现 |
| 报告交付 | HTML、JSON、研判 Markdown、CSV、IOC、SARIF、manifest | `--out /tmp/bla-demo-p0` | 任意日志样本 | 已本地复现 |
| `cn-hvv` 画像 | Log4Shell、Webshell、国内重保常见痕迹 | `--profile cn-hvv` + P0/Web 样本 | SecRepo Web、真实 WAF 导出 | 已本地复现 |
| YAML 规则扩展 | Web 攻击规则加载和元数据校验 | `bla/rules/web_attacks.yaml` | 企业自定义规则库 | 已本地复现 |
| 误报压制 | 可信扫描器、维护窗口、规则级 suppress | `--allowlist allowlist.json` | 运维窗口/漏洞扫描记录 | 需现场配置 |
| 远程只读采集 | SSH 拉取远程日志子集后本地分析 | `remote-log --help`、单元测试 | 授权 Linux 主机 | 接口已具备；缺真实目标截图 |
| 日志源采集矩阵 | P0/P1/P2 日志拉取优先级 | `--list-log-sources` | HVV/重保现场日志源 | 已本地复现 |
| 性能基准 | 大文件逐行解析、吞吐、峰值内存 | `benchmark --size-mb 1` | Loghub OpenSSH/Windows/Apache | 已本地复现基准；大公开集候选 |
| CI 门禁 | `--exit-on`、SARIF、规则校验 | CLI smoke + release check | GitHub Actions / Code Scanning | 已具备 |

## 演示截图

真实终端截图按实际演示场景单独生成；当前报告保留要截取的命令和画面重点，避免把未确认截图或临时截图写入 README。

### Linux auth.log 终端演示

重点展示：

- 自动识别 Linux Auth Log。
- 31 条事件、5 个告警、1 个关联案件。
- 暴力破解、密码喷洒、root 直接登录、新建用户等告警。
- ATT&CK 阶段、应急案件视图、Top 攻击源 IP 和处置建议。

复现命令：

```bash
python3 bla_cli.py sample_logs/auth.log --max-alerts 5 --exit-on none
```

### HVV/重保 P0 多源案件演示

重点展示：

- WAF、应用、EDR、DNS、代理、防火墙 6 类日志源合成一个 P0 案件。
- Log4Shell/JNDI、Webshell beacon、DNS 可疑查询、代理恶意分类、防火墙大流量外联。
- Incident 视图给出攻击路径还原、关键证据、建议补采和处置动作。
- `--out` 同时生成 HTML、JSON、研判 Markdown、CSV、IOC、SARIF、manifest。

复现命令：

```bash
python3 bla_cli.py tests/fixtures/p0/hvv_chain.jsonl \
  --type p0-security \
  --profile cn-hvv \
  --out /tmp/bla-demo-p0 \
  --max-alerts 5 \
  --exit-on none
```

### Remote Collector 帮助入口

重点展示：

- `remote-log` 是只读采集远程日志子集后在本机分析。
- 支持 `--tail`、`--grep`、`--max-bytes`、`--audit-json` 和标准报告输出。
- 真实演示需要一台明确授权的 SSH 目标。

复现命令：

```bash
python3 bla_cli.py remote-log --help
```

## 案例 01：SecRepo Linux auth.log

**适合讲什么**：SSH 暴力破解、密码喷洒、失败登录聚合、Top 攻击源、Top 用户、IOC 提取、syslog 年份补齐、终端报告、JSON/HTML/IOC 输出。

公开来源：

- SecRepo 首页：https://www.secrepo.com/
- 样本地址：https://www.secrepo.com/auth.log/auth.log.gz
- 已有实测记录：`docs/secrepo-sample-validation.md`

本地快速演示：

```bash
python3 bla_cli.py sample_logs/auth.log --max-alerts 5 --exit-on none
```

公开样本复现：

```bash
curl -L -o auth.log.gz https://www.secrepo.com/auth.log/auth.log.gz
gunzip -f auth.log.gz
python3 bla_cli.py auth.log \
  --syslog-year 2015 \
  --out report/secrepo-auth \
  --exit-on none
```

已记录结果摘要：

| 指标 | 结果 |
| --- | ---: |
| 原始行数 | 86,839 |
| 解析事件 | 27,075 |
| 告警 | 624 |
| 风险评分 | 100/100 |
| 主要告警 | SSH 暴力破解、密码喷洒、Top IP、Top User、IOC |

发布展示建议：

- 先跑本地 `sample_logs/auth.log`，速度快、输出稳定。
- 再展示 SecRepo 验证记录，说明不是只靠手写 fixture。
- 讲清楚 `--syslog-year` 的价值：syslog 原生日志通常没有年份，BLA 允许补齐年份以便跨源时间线对齐。

## 案例 02：SecRepo Web access.log

**适合讲什么**：Apache/Nginx Combined 解析、路径探测、Web 攻击规则、`cn-hvv` 画像、URL/源 IP IOC、HTML/JSON/IOC 报告。

公开来源：

- SecRepo Web 日志目录：https://www.secrepo.com/self.logs/
- 示例文件：https://www.secrepo.com/self.logs/access.log.2017-05-15.gz
- 已有实测记录：`docs/secrepo-sample-validation.md`

复现命令：

```bash
curl -L -o access.log.gz https://www.secrepo.com/self.logs/access.log.2017-05-15.gz
gunzip -f access.log.gz
python3 bla_cli.py access.log \
  --profile cn-hvv \
  --out report/secrepo-web \
  --exit-on none
```

已记录结果摘要：

| 指标 | 结果 |
| --- | ---: |
| 原始行数 | 2,928 |
| 解析事件 | 236 |
| 告警 | 2 |
| 风险评分 | 100/100 |
| 主要验证能力 | Web access 解析、敏感路径探测、`cn-hvv`、IOC |

发布展示建议：

- Web 样本适合和 `--rules` 一起讲，证明 BLA 不是只写死检测器。
- 如果要扩展实战说服力，可以从同一目录挑多天 access.log 做目录批量分析。

## 案例 03：Windows XML / EVTX 攻击样本

**适合讲什么**：Windows 登录事件、RDP 专项、4624/4625 登录、4688 进程创建、Sysmon/安全日志、EVTX 原始文件支持边界。

公开来源：

- EVTX-ATTACK-SAMPLES：https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Mordor / Security-Datasets：https://github.com/OTRF/Security-Datasets

本地 XML 演示：

```bash
python3 bla_cli.py sample_logs/windows_rdp_sample.xml \
  --rdp \
  --max-alerts 5 \
  --exit-on none

python3 bla_cli.py sample_logs/windows_4688_sample.xml \
  --max-alerts 5 \
  --exit-on none
```

EVTX 公开样本演示：

```bash
pip install -U "blueteam-log-analyzer[evtx]"
python3 bla_cli.py /path/to/EVTX-ATTACK-SAMPLES \
  --type windows-evtx \
  --out report/evtx-attack-samples \
  --exit-on none
```

Windows 原生命令导出 XML：

```powershell
wevtutil qe Security /f:RenderedXml /e:Events /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]" > Security.xml
```

发布展示建议：

- `--rdp` 专项适合给蓝队值班和应急排查看，因为它会过滤掉没有远程来源的噪声登录。
- EVTX-ATTACK-SAMPLES 覆盖多类 ATT&CK 技术，但文件较大且有 GPL 授权约束，不建议直接随发布包内置。
- 如果要做发布前完整演示，建议从 EVTX-ATTACK-SAMPLES 选 3 组：Credential Access、Lateral Movement、Persistence。

## 案例 04：HVV/重保 P0 多源关联案件

**适合讲什么**：WAF、应用、EDR、DNS、代理、防火墙多源归一化，Incident 关联，攻击拓扑还原，建议补采，处置动作。

本地复现：

```bash
python3 bla_cli.py tests/fixtures/p0/hvv_chain.jsonl \
  --type p0-security \
  --profile cn-hvv \
  --out /tmp/bla-demo-p0 \
  --max-alerts 5 \
  --exit-on none
```

本轮本机输出摘要：

| 指标 | 结果 |
| --- | ---: |
| 解析事件 | 6 |
| 告警 | 5 |
| Incident | 1 |
| 风险评分 | 94/100 |
| 关联日志源 | application、dns、edr、firewall、proxy、waf |

可对接公开数据源：

- Splunk BOTS v3：https://github.com/splunk/botsv3
- Mordor / Security-Datasets：https://github.com/OTRF/Security-Datasets

发布展示建议：

- 这条是最能体现 BLA 产品价值的演示，因为它不是单日志告警，而是把多源证据组织成案件。
- 演示时重点讲“BLA 输出给应急人员的是案件、证据、时间线和补采建议”，不是单纯列一堆命中规则。
- Splunk BOTS 需要先从 Splunk 中导出 CSV/JSON，或写一个转换脚本转成 BLA 的 P0 JSONL 字段。

## 案例 05：报告交付包

**适合讲什么**：离线 HTML、结构化 JSON、Excel 可读 CSV、IOC、SARIF、manifest 证据清单。

复现命令：

```bash
python3 bla_cli.py tests/fixtures/p0/hvv_chain.jsonl \
  --type p0-security \
  --profile cn-hvv \
  --out /tmp/bla-demo-p0 \
  --exit-on none
```

应检查的输出：

```text
/tmp/bla-demo-p0/
  index.html
  report.json
  incident_brief.md
  incident_evidence.csv
  events.csv
  iocs.txt
  report.sarif
  manifest.json
```

展示口径：

- `index.html`：给应急负责人和客户阅读。
- `report.json`：给平台、工单、二次分析消费。
- `incident_brief.md`：给复盘、工单和客户交付，保留确认事实、研判假设和不能确认项。
- `incident_evidence.csv`：给复核人员快速查看研判摘要实际引用的原始证据。
- `events.csv`：给 Excel 复核和人工筛选。
- `iocs.txt`：给封禁、狩猎和情报沉淀。
- `report.sarif`：给 CI 或 Code Scanning 一类系统消费。
- `manifest.json`：记录输入、参数、hash、远程采集上下文等证据链信息。

## 案例 06：误报压制与 allowlist

**适合讲什么**：真实客户现场不会只看“多报”，还要能解释为什么某些已知扫描器、维护窗口和可信账号可以被压制。

示例 allowlist：

```json
{
  "trusted_ips": ["10.0.0.5"],
  "trusted_accounts": ["deploy"],
  "maintenance_windows": [
    {
      "name": "weekly patch window",
      "start": "2026-03-15T09:00:00",
      "end": "2026-03-15T10:00:00",
      "assets": ["webserver"]
    }
  ],
  "suppressions": [
    {
      "rule_id": "BRUTE_FORCE",
      "src_ip": "198.51.100.100",
      "reason": "authorized password audit"
    }
  ]
}
```

复现命令：

```bash
python3 bla_cli.py sample_logs/auth.log \
  --allowlist allowlist.json \
  --out /tmp/bla-demo-allowlist \
  --exit-on none
```

发布展示建议：

- 这项能力适合放在“成熟度”部分讲，不一定作为第一屏演示。
- 它回应的是客户最常见问题：工具会不会把漏洞扫描、堡垒机巡检和维护操作都当攻击。

## 案例 07：规则扩展与规则质量门禁

**适合讲什么**：BLA 的 Web 攻击检测可以通过 YAML 规则扩展，并且发布前会校验规则元数据和正则。

复现命令：

```bash
python3 bla_cli.py validate-rules --strict-metadata
python3 bla_cli.py access.log --rules bla/rules --profile cn-hvv --out report/web-rules --exit-on none
```

本轮本机校验结果：

| 指标 | 结果 |
| --- | ---: |
| 规则数 | 3 |
| 编译模式数 | 4 |
| errors | 0 |
| warnings | 0 |

发布展示建议：

- 重点展示“规则能被审查和门禁”，避免客户误以为这是不可维护的黑盒。
- 新规则应包含 id、name、severity、MITRE、pattern、description、recommendation。

## 案例 08：远程只读采集 Remote Collector

**适合讲什么**：目标机不需要安装 BLA；BLA 通过 SSH 只读拉取日志子集，本机分析并保留审计记录。

帮助入口：

```bash
python3 bla_cli.py remote-log --help
```

授权目标演示模板：

```bash
python3 bla_cli.py remote-log root@10.0.0.20 /var/log/auth.log \
  --tail 2000 \
  --grep "Failed password" \
  --audit-json /tmp/bla-remote-audit.json \
  --out /tmp/bla-remote-auth \
  --exit-on none
```

展示口径：

- `--tail` 控制采集范围，适合先做低扰动排查。
- `--grep` 用于只采集关键行。
- `--max-bytes` 限制单个输入最大采集大小。
- `--audit-json` 记录远程采集行为，方便事后审计。

当前边界：

- 本报告未连接真实远程目标。
- 发布前如要把 Remote Collector 讲成重点能力，建议补一张授权测试机截图和一份 `audit-json` 示例。

## 案例 09：HVV/重保日志源采集矩阵

**适合讲什么**：BLA 不只是分析工具，也能指导第一轮日志拉取顺序。

复现命令：

```bash
python3 bla_cli.py --list-log-sources
```

展示重点：

- P0：第一轮必采，支撑入口确认、账号突破、主机失陷、C2、横向移动、数据访问。
- P1：第二轮补全攻击链。
- P2：溯源、影响评估、运营支撑材料。

适合演示的 P0 项：

- WAF / Web 安全网关日志。
- Web 服务器 access.log。
- VPN / SSL VPN / 零信任登录日志。
- 堡垒机登录与命令审计。
- AD / 域控 Security 日志。
- EDR / XDR 告警与终端行为。
- Windows 安全日志 / Sysmon。
- Linux auth.log / secure / auditd。
- DNS、代理、防火墙、NDR、数据库审计、云审计、Kubernetes API 审计。

## 案例 10：性能和大文件候选

**适合讲什么**：逐行解析、并行 `-j N`、benchmark、真实大日志候选。

本地基准：

```bash
python3 bla_cli.py benchmark --size-mb 1
```

本轮本机结果：

| 指标 | 结果 |
| --- | ---: |
| size | 1.00 MB |
| events | 6,833 |
| alerts | 44 |
| incidents | 4 |
| throughput | 2.74 MB/s |
| event rate | 18,721 events/s |

公开候选：

- Loghub OpenSSH：适合 Linux 认证日志大样本。
- Loghub Apache：适合 Web 错误日志和通用日志解析。
- Loghub Windows：适合 Windows 事件日志大样本，但体积较大。

发布展示建议：

- README 不宜写死某台机器的 benchmark 数值为承诺，只能写“本机参考结果”。
- 真正面向客户时，应在客户同等硬件和相近日志结构上重新跑基准。

## 案例 11：CyberDefenders Hammered 蓝队实验

**适合讲什么**：Linux 入侵排查、执行、持久化、防御规避、凭据访问和发现活动。

公开来源：

- https://cyberdefenders.org/blueteam-ctf-challenges/hammered/

使用建议：

- Hammered 需要登录 CyberDefenders 后下载实验文件。
- 适合做人工研判流程演示：先用 BLA 快速扫 auth/syslog/access，再人工回答挑战问题。
- 不建议把题目答案硬编码进 BLA；应把它作为“未知样本分析能力”的展示。

## 案例 12：Splunk BOTS 多源 SOC 数据

**适合讲什么**：多源 SOC 数据、云日志、Windows/Sysmon、Linux、Web、代理、DNS、端点和安全设备日志。

公开来源：

- BOTS v3：https://github.com/splunk/botsv3
- Splunk Security Datasets：https://github.com/splunk/securitydatasets

适配方式：

1. 下载 BOTS v3 并按官方方式导入 Splunk。
2. 按 sourcetype 导出 CSV 或 JSON。
3. 将 `access_combined`、`linux_secure`、`xmlwineventlog`、`aws:cloudtrail`、`stream:dns`、`stream:http` 等映射到 BLA 支持格式或 P0 JSONL。
4. 运行 BLA 并检查 Incident、IOC、时间线和报告输出。

当前边界：

- BOTS 是 pre-indexed Splunk 数据，不能直接当普通日志文件丢给 BLA。
- 要把它变成稳定演示，需要一个导出/转换脚本；这适合放到后续建设批次。

## 发布前建议演示流程

建议实际演示控制在 8 到 12 分钟：

1. 打开 README，点击“演示案例库与功能覆盖报告”。
2. 跑 `sample_logs/auth.log`，展示暴力破解、密码喷洒、Incident、ATT&CK、Top IP。
3. 跑 `tests/fixtures/p0/hvv_chain.jsonl`，展示多源 P0 案件、攻击路径、补采建议、输出包。
4. 打开 `/tmp/bla-demo-p0/index.html`，展示离线 HTML 报告。
5. 展示 `/tmp/bla-demo-p0/manifest.json`，说明输入 hash 和参数证据链。
6. 跑 `validate-rules --strict-metadata`，说明规则可治理。
7. 跑 `remote-log --help`，说明远程只读采集入口，并明确真实目标需要授权。
8. 最后展示公开数据源列表，说明下一步可以用 EVTX-ATTACK-SAMPLES、Loghub、Mordor、BOTS 扩充长期样本库。

## 发布前不足和下一步

当前材料已经覆盖 BLA 的核心功能面，但还有四个值得优化的点：

1. **远程采集缺真实目标截图**：建议准备一台授权 Linux 测试机，跑一次 `remote-log --tail --grep --audit-json --out`。
2. **EVTX 真实样本还没纳入本地验证记录**：建议从 EVTX-ATTACK-SAMPLES 选 3 个小样本，形成 Windows 专项记录。
3. **BOTS/Mordor 还需要转换脚本**：这些数据源价值高，但格式更偏 SIEM/JSON，需要把导出流程产品化。
4. **README 首页不应塞太长**：首页保留入口、摘要和截图即可，详细内容留在本报告。

## 来源清单

- SecRepo Security Data Samples Repository：https://www.secrepo.com/
- SecRepo self.logs：https://www.secrepo.com/self.logs/
- EVTX-ATTACK-SAMPLES：https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Loghub：https://github.com/logpai/loghub
- Mordor / Security-Datasets：https://github.com/OTRF/Security-Datasets
- CyberDefenders Hammered：https://cyberdefenders.org/blueteam-ctf-challenges/hammered/
- Splunk BOTS v3：https://github.com/splunk/botsv3
