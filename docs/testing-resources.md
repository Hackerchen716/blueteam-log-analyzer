# BLA 测试资源推荐清单

这份清单用于评估 BlueTeam Log Analyzer (BLA) 的解析、检测、IOC 提取、攻击链和报告输出能力，可作为人工验证和回归测试样本来源。

## Windows 事件日志

### EVTX-ATTACK-SAMPLES

- 地址：https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- 类型：Windows EVTX 攻击样本
- 适合验证：凭据访问、权限提升、防御规避、横向移动、Sysmon 事件、PowerShell 事件
- 已复验小样本：`Powershell_4104_MiniDumpWriteDump_Lsass.evtx`、`CA_sysmon_hashdump_cmd_meterpreter.evtx`、`LM_WMI_4624_4688_TargetHost.evtx`、`LM_Remote_Service02_7045.evtx`、`sysmon_20_21_1_CommandLineEventConsumer.evtx`、`DE_104_system_log_cleared.evtx`、`UACME_59_Sysmon.evtx`
- BLA 用法：

```bash
pip install -U "blueteam-log-analyzer[evtx]"
bla /path/to/EVTX-ATTACK-SAMPLES --html evtx_report.html --json evtx_report.json
```

## Linux 认证日志

### SecRepo auth.log

- 地址：https://www.secrepo.com/auth.log/auth.log.gz
- 类型：Linux auth.log
- 适合验证：SSH 暴力破解、密码喷洒、失败登录聚合、Top IP、时间线
- BLA 用法：

```bash
curl -L -o auth.log.gz https://www.secrepo.com/auth.log/auth.log.gz
gunzip auth.log.gz
bla auth.log --syslog-year 2015 --html auth_report.html --json auth_report.json --ioc auth_iocs.txt
```

## Web 访问日志

### SecRepo self.logs access.log

- 地址：https://www.secrepo.com/self.logs/
- 类型：Apache/Nginx Combined 风格 Web 访问日志，按日期拆分
- 适合验证：SQL 注入、XSS、路径遍历、命令注入、扫描器识别、IOC 提取
- BLA 用法：

```bash
curl -L -o access.log.gz https://www.secrepo.com/self.logs/access.log.2017-05-15.gz
gunzip access.log.gz
bla access.log --profile cn-hvv --html web_report.html --json web_report.json --ioc web_iocs.txt
```

## 多源 HVV/重保近似数据集

真实 HVV/重保现场客户日志通常不能公开流通。下面这些来源是公开可访问、可合法复现的近似数据，可用于扩充发布前人工验证；原始数据不应随发布包内置。

| 数据源 | 地址 | 适合验证 | BLA 接入方式 |
|--------|------|----------|--------------|
| SecRepo Linux/Web logs | https://www.secrepo.com/ | SSH 爆破、密码喷洒、Web 扫描、敏感路径探测 | 可直接下载到临时目录后用 `bla` 分析 |
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Windows Security/Sysmon、凭据访问、横向移动、持久化、权限提升 | 安装 `blueteam-log-analyzer[evtx]` 后分析 `.evtx`，或先转 XML |
| OTRF Security-Datasets / Mordor | https://github.com/OTRF/Security-Datasets | ATT&CK 技术链路、Windows/Sysmon、恶意与正常样本对照 | Windows EventLog JSON/JSONL 可直接走 `windows-json` parser；安全设备 CSV/JSONL 继续走 P0 |
| Splunk BOTS v3 | https://github.com/splunk/botsv3 | 多源 SOC 案件、Web、云审计、Linux、代理、防火墙、Office 365 | 先导入 Splunk，再导出 CSV/JSON 或写转换脚本接入 BLA |
| Splunk Attack Data | https://github.com/splunk/attack_data | 单技术检测回归、T1003 等 ATT&CK 技术样本 | 使用 Git LFS 按需拉取小目录，优先选单日志文件验证 |
| 本地靶场 EDR Excel 导出 | 不公开分发 | EDR 进程事件、无签名执行、伪装软件、临时目录投放、随机名样本、SYSTEM 级计划任务/ACL/portproxy 线索 | 原始 `.xlsx` 不入仓；可用 `--type edr-xlsx` 或自动识别本地分析 |

### 已复验 Splunk Attack Data / OTRF 小样本

- Splunk Attack Data：
  - `datasets/attack_techniques/T1071.004/long_dns_query/dns-sysmon.log`
  - `datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log`
  - `datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl_upload.log`
  - `datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log`
  - `datasets/attack_techniques/T1562.001/win_defend_service_stop/windows-sysmon.log`
  - `datasets/attack_techniques/T1548.002/ssa_eventvwr/windows-sysmon-registry.log`
- OTRF Security-Datasets：
  - `datasets/atomic/windows/defense_evasion/host/auditpol_system_user_auditpolicy_modification.zip`
  - `datasets/atomic/windows/defense_evasion/host/reg_disable_eventlog_service_startuptype_modification_via_registry.zip`
  - `datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip`
  - `datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper.zip`

本批公开样本用于验证 Windows XML 单引号命名空间、Sysmon DNS tunnel / DNS exfil、auditpol 防御规避、eventvwr/mscfile UAC bypass 和 OTRF Windows JSON EventLog parser。原始样本只保存在 `/tmp/bla-splunk-otrf-review-20260530`，不进入仓库。

OTRF JSON 专项复验结果：4 个 JSON 文件全部识别为 `Windows Event Log (JSON)`，共 22,080 事件、7 告警、1 incident；合集复跑后 Splunk + OTRF 共 32,750 事件、9 告警、IOC 629 项。

### 已复验本地 EDR Excel 导出样本

- 文件：`日志查询 20260204_171209.xlsx`
- SHA256：`7753269849198d3da3998968e6c97d043f2c63f6a2a73c46a08e32acc4a9e321`
- 说明：样本只保存在本地下载目录，不进入仓库，不随发布包分发。
- 复验结果：识别为 `EDR Excel Export`，8737 条进程事件、1 个 EDR 高危终端告警、1 个 incident；关键线索包含用户目录无签名伪装进程、`II-1/II-10` 临时目录投放、随机名可执行文件、WebRoot 可执行文件、随机计划任务删除、随机目录 ACL 修改和 portproxy reset 补采线索。

## 蓝队靶场

### CyberDefenders Hammered

- 地址：https://cyberdefenders.org/blueteam-ctf-challenges/hammered/
- 类型：Linux 入侵排查挑战
- 适合验证：认证日志分析、持久化线索、攻击时间线、处置建议
- 说明：实验文件通常需要登录 CyberDefenders 后下载。

## 验证项

样本运行后可检查：

- 是否正确识别日志类型
- 是否产生合理的严重/高危告警
- IOC 导出是否包含攻击 IP、URL、Webshell 路径、用户和命令
- HTML 报告是否可离线打开，且不会执行日志中的 HTML/JS 内容
- `--profile cn-hvv` 是否能提升国内常见漏洞和 Webshell 痕迹的优先级
- `--syslog-year` 是否让 Linux auth.log 与其他日志时间线对齐

## 回归测试命令

```bash
python3 -m compileall -q bla bla_cli.py setup.py tests
python3 -m unittest discover -s tests -v
```
