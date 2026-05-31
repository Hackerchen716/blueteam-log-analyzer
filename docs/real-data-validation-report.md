# BLA 真实数据逐条验收报告

本报告记录对公开真实样本的本地逐条复核结果。原始样本只保存在 `/tmp`，不进入仓库；完整交付报告保存在对应 `/tmp` 报告目录。

## 数据源与输出

| 编号 | 数据源 | 本地样本 | 完整报告目录 | 结论 |
|------|--------|----------|--------------|------|
| 1 | SecRepo `auth.log.gz` | `/tmp/bla-hvv-real-data-rAgDex/auth.log` | `/tmp/bla-real-review-rAgDex/auth/report` | 通过，发现并修复 OpenSSH preauth 重复行噪声 |
| 2 | SecRepo `access.log.2017-05-15.gz` | `/tmp/bla-hvv-real-data-rAgDex/access.log` | `/tmp/bla-real-review-rAgDex/access/report` | 通过，发现并修复普通 3xx/304 Web 事件噪声 |
| 3 | EVTX-ATTACK-SAMPLES Windows 小样本 | `/tmp/bla-evtx-real-data-api-db8068` | `/tmp/bla-evtx-real-review-api-db8068/after` | 通过，修复 Sysmon 10 误标、4104 LSASS dump 漏识别、WMI 持久化/横向移动链路缺口 |
| 4 | Splunk Attack Data / OTRF Security-Datasets Windows 样本 | `/tmp/bla-splunk-otrf-review-20260530` | `/tmp/bla-splunk-otrf-review-20260530/after3` | 通过，修复 Windows XML 单引号命名空间兼容，新增 DNS 外传、auditpol 防御规避和 UAC registry 检测 |
| 5 | 本地靶场 EDR Excel 导出样本 | 本地下载目录，SHA256 `7753269849198d3da3998968e6c97d043f2c63f6a2a73c46a08e32acc4a9e321` | 终端复验，未落盘入仓 | 通过，新增 EDR Excel parser，识别伪装安装包执行链、SYSTEM 级计划任务删除、随机目录 ACL 修改和 portproxy reset |

每个报告目录均包含 `index.html`、`report.json`、`events.csv`、`iocs.txt`、`report.sarif`、`manifest.json`。

## 2026-05-31 本地 EDR Excel 导出样本

数据来源：用户本地靶场导出的 EDR 进程事件 Excel，文件名 `日志查询 20260204_171209.xlsx`。原始样本不进入仓库，不随发布包分发。

样本信息：

| 文件 | 大小 | 行数 | SHA256 |
|------|-----:|-----:|--------|
| `日志查询 20260204_171209.xlsx` | 879 KB | 8738 行，含 8737 条数据行 | `7753269849198d3da3998968e6c97d043f2c63f6a2a73c46a08e32acc4a9e321` |

基线表现：

```bash
python3 bla_cli.py '/Users/chenjianfang/Downloads/日志查询 20260204_171209.xlsx' --no-color --max-alerts 10 --exit-on none
```

修复前识别为 `通用日志`，只解析 ZIP/XML 文本片段，输出 6106 个信息级事件、0 告警。

修复后表现：

| 指标 | 结果 |
|------|-----:|
| 日志类型 | `EDR Excel Export` |
| 解析事件 | 8737 |
| 高危事件 | 22 |
| 中危事件 | 39 |
| 告警 | 1 |
| Incident | 1 |
| 解析耗时 | 约 429-465 ms |

关键线索：

- 用户目录无签名伪装进程：`TencentttMeeti5681.exe`。
- 临时目录投放链：`II-1.exe` / `II-10.exe` 释放并执行 `II-1.tmp` / `II-10.tmp`。
- 随机名可执行文件：`3Fv6Bsq.exe`。
- WebRoot 可执行文件：`C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT.exe`。
- SYSTEM 级清理/权限动作：`schtasks /delete` 删除随机任务、`icacls` 修改 `NCElSz\c8XAtk` 与 `rMmZhp\ewWB4p` 随机目录 ACL。
- `elevation_service.exe -> netsh.exe interface portproxy reset` 重复出现 20 次，作为网络配置/补采线索展示，未直接断言 C2 或外传。

误报控制：

- 未把样本答案或病毒家族写入规则。
- 品牌伪装判断要求用户目录可执行文件同时无签名，签名正常的安装器不会仅因路径和品牌名升高危。
- 远程线程事件只有叠加无签名、用户目录、随机名、投放等信号才升为高危；普通远程线程观察项降为中危。
- `Guangzhou TEC Solutions Co., Ltd.` 等安全组件 DLL 在全表大量出现，作为上下文保留，不再单独作为高危核心证据。

回归验证：

- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_edr_xlsx_auto_parse_detects_unsigned_fake_software_chain tests/test_parsers.py::ParserRegressionTests::test_edr_xlsx_content_parser_supports_tsv_rows tests/test_detection.py::DetectionRegressionTests::test_detector_registry_selector_limits_candidate_events tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_edr_vendor_detection_fields_detect_credential_dumping` 通过。
- `python3 -m pytest -q tests/test_parsers.py tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe` 通过，58 个相关用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，228 个测试通过。
- `python3 -m unittest discover -s tests -v` 通过，228 个测试通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，0 error / 0 warning。

## 2026-05-30 Splunk Attack Data / OTRF Windows 样本

数据来源：

- https://github.com/splunk/attack_data
- https://github.com/OTRF/Security-Datasets

本轮仅下载 6 个 Splunk Windows XML/LFS 小样本和 4 个 OTRF Windows JSON zip 到 `/tmp/bla-splunk-otrf-review-20260530`；不将第三方原始样本放入仓库。

样本清单：

| 来源 | 样本 | SHA256 |
|------|------|--------|
| Splunk | `T1071.004/long_dns_query/dns-sysmon.log` | `665351a29bf5545503fb572c808bf9ebf157e74ec6dcc8a098890551db6932ed` |
| Splunk | `T1048.003/nslookup_exfil/windows-sysmon.log` | `5d7d8b9acd80ad09e962446a328901b29ba760e3b94aeb6b8ad41f0caddae27f` |
| Splunk | `T1105/atomic_red_team/windows-sysmon_curl_upload.log` | `af1602ccd961b0ae04cd5ca8c5c9dcbde01df6f86381bd9da67e6a3add5951ff` |
| Splunk | `T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log` | `a417ec3d8d48c9cdcf4d5bcfc834fe100ba8a03105bcf08305f5af40a830b363` |
| Splunk | `T1562.001/win_defend_service_stop/windows-sysmon.log` | `f9dc84160d71a405117cbf792cb724bfe2779d1e0406e9be387ba591ceaacd71` |
| Splunk | `T1548.002/ssa_eventvwr/windows-sysmon-registry.log` | `ba231cc7cbe0690e4e77e0d9dbfcd9f7cca43f07946f80f37c77cc2e3b0d817d` |
| OTRF | `auditpol_system_user_auditpolicy_modification.zip` | `5eb1776e7e9f79060a87ed9efcce0eebbab7940f8f51db8b2d67368c64e2187d` |
| OTRF | `reg_disable_eventlog_service_startuptype_modification_via_registry.zip` | `d79d5a13fbb1e7957d748955a1be5c68294e58d322b76e41393d6987fe769656` |
| OTRF | `cmd_bitsadmin_download_psh_script.zip` | `8fb7bc9f3d82f672dc39a55e50006137aa540c4a9860acdcc5d08a4fd609b594` |
| OTRF | `empire_uac_shellapi_fodhelper.zip` | `b8cc7aae826f5e4aea3ea47b2b6db69b062c39201de8de9621d5081622d3c504` |

运行命令：

```bash
python3 bla_cli.py \
  /tmp/bla-splunk-otrf-review-20260530/splunk \
  /tmp/bla-splunk-otrf-review-20260530/otrf \
  --profile cn-hvv \
  --no-color \
  --max-alerts 40 \
  --exit-on none \
  --out /tmp/bla-splunk-otrf-review-20260530/after3
```

基线与修复后对比：

| 指标 | 修复前 | 修复后 |
|------|-------:|-------:|
| 解析事件 | 20,980 | 31,650 |
| 告警 | 7 | 11 |
| Incident | 1 | 3 |
| 风险 | `100/critical` | `100/critical` |
| IOC | - | 6,240 |

回归验证：

- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py` 通过，98 个相关回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，213 个测试通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，0 error / 0 warning。
- `python3 scripts/release_check.py` 通过，包含 1 MB benchmark 与 1 MB memory benchmark。
- `git diff --check` 通过。

逐条复查结论：

| 检查项 | 修复前 | 修复后 | 结论 |
|--------|--------|--------|------|
| Splunk Windows XML 默认命名空间使用单引号 | 6 个 XML 样本中 5 个解析为 0 事件 | 6 个 XML 样本均解析，合计 10,670 条 Sysmon 事件 | 修复 XML 兼容性，不再静默空报告 |
| `auditpol /clear`、`/remove`、`/success:disable`、`/failure:disable` | 仅普通 Sysmon 进程创建 | `EVAS-002`，8 条 `T1562.002` 防御规避事件 | 修复 auditpol tampering 漏报 |
| `nslookup` 携带 base64 数据、PowerShell 长编码 DNS 查询 | 无外传聚合告警 | `EXFIL-002` 168 条，`T1048.003`；同时以 `C2-001 / T1071.004` 低噪声提示 DNS tunnel 外联 | 修复 DNS 外传/C2 弱识别 |
| `HKU\\SID_Classes\\mscfile\\shell\\open\\command` | 仅普通注册表持久化中危事件 | `PRIV-006`，2 条 `T1548.002` UAC bypass 事件 | 修复 eventvwr/mscfile UAC registry 漏报 |
| AD `_ldap._tcp..._msdcs` DNS SRV 查询 | 初版增强中会被 `ldap` 关键词误归入 C2 | 不再触发 C2；仅保留普通 DNS 事件 | 修复正常域控发现流量误报 |

新增或变化的告警：

| 告警 | 技术 | 说明 |
|------|------|------|
| `EVAS-002 审计策略修改` | `T1562.002` | 识别 Sysmon 进程命令里的 auditpol 清除、移除、禁用和 SDDL 篡改 |
| `PRIV-006 UAC 绕过痕迹` | `T1548.002` | 识别 HKCU/HKU Software Classes 相关 UAC bypass 注册表路径 |
| `EXFIL-002 DNS 数据外传/隧道` | `T1048.003` | 识别 DNS 查询命令中的编码载荷和可疑长编码子域 |
| `C2-001 Sysmon 可疑命令控制/外联` | `T1071.004` | 对 DNS tunnel 行为给出命令控制视角，避免把 AD `_ldap` SRV 查询当回连 |

剩余观察：

- OTRF Windows JSON 走 P0/generic JSON 适配器的问题已在后续专项复跑中通过独立 `windows-json` parser 处理；见下一节。
- 后续 CLI bundle manifest 专项已修复同名 basename provenance：普通 `bla_cli.py --out` 路径现在复用 pipeline 的唯一相对展示名，`manifest.inputs` 与 `parsed_files` 均保留 `host-a/access.log` 这类非绝对输入标签，并继续记录输入 sha256。

### OTRF Windows JSON 专项复跑

新增独立 `windows-json` parser 后，OTRF JSON 不再走 P0/generic JSON 适配器。该 parser 通过 ParserRegistry 注册在 `p0-security` 之前，只把 Windows EventLog JSON/JSONL/JSON sequence 转为 `LogEvent`，检测仍由 detector 层完成。

运行命令：

```bash
PYTHONPATH=. /usr/bin/python3 bla_cli.py \
  /tmp/bla-splunk-otrf-review-20260530/otrf \
  --profile cn-hvv \
  --no-color \
  --max-alerts 20 \
  --exit-on none \
  --out /tmp/bla-splunk-otrf-review-20260530/otrf-json-after2
```

OTRF JSON 子集结果：

| 指标 | 结果 |
|------|-----:|
| JSON 文件 | 4 |
| 解析事件 | 22,080 |
| 告警 | 7 |
| Incident | 1 |
| IOC | 181 |
| 风险 | `100/critical` |

主要告警：

| 告警 | 技术 | 事件数 | 说明 |
|------|------|-------:|------|
| `EVAS-001 日志清除 - 反取证行为` | `T1070.001` | 4 | Security/System 日志清除事件 |
| `EVAS-002 审计策略修改` | `T1562.002` | 75 | OTRF auditpol 修改样本 |
| `CRED-001` / `CRED-002` | `T1003.001` | 138 / 138 | LSASS 访问相关凭据访问视角 |
| `EXEC-001 高危 PowerShell 执行` | `T1059.001` | 2 | Empire/fodhelper 样本中的高危 PowerShell |
| `PRIV-006 UAC 绕过痕迹` | `T1548.002` | 4 | `ms-settings\\Shell\\Open\\command` UAC registry |
| `EXEC-002 Living-off-the-Land (LOLBins)` | `T1218` | 2 | bitsadmin 下载执行链 |

Splunk + OTRF 合集复跑：

```bash
PYTHONPATH=. /usr/bin/python3 bla_cli.py \
  /tmp/bla-splunk-otrf-review-20260530/splunk \
  /tmp/bla-splunk-otrf-review-20260530/otrf \
  --profile cn-hvv \
  --no-color \
  --max-alerts 40 \
  --exit-on none \
  --out /tmp/bla-splunk-otrf-review-20260530/windows-json-after
```

合集结果为 32,750 事件、9 告警、1 incident、IOC 629 项。所有 OTRF JSON 文件均显示为 `Windows Event Log (JSON)`，Splunk XML 样本仍显示为 `Windows Event Log (XML)`。Windows EventLog 多源 incident 标题已从误导性的 `P0 多源关联案件` 修正为 `多源关联案件`。

回归验证：

- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest tests.test_parsers tests.test_detection -v` 通过，101 个相关回归用例通过。
- `PYTHONPATH=. /usr/bin/python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest discover -s tests -v` 通过，216 个测试通过。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py validate-rules --strict-metadata` 通过。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1` 通过，1.36 MB/s。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1 --memory` 通过，peak memory 35.74 MB。
- `git diff --check` 通过。

验证限制：

- 本小节记录的是当时桌面环境限制：默认 `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3` 曾出现 `python3 -c 'print("hi")'` 卡住，未能在该轮复跑原始 `python3 -m pytest -q` 与 `python3 scripts/release_check.py`。后续已在正常 Python 3.12 环境补跑完整门禁，见下方“回归与验证”和 `docs/releases/v1.4.4.md`。

## 2026-05-30 EVTX-ATTACK-SAMPLES Windows 小样本

数据来源：

- https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

本轮仅下载 7 个小 EVTX 文件到 `/tmp/bla-evtx-real-data-api-db8068`，覆盖凭据访问、横向移动、持久化、防御规避和 UAC/提权近似样本；不将第三方原始 EVTX 放入仓库。

样本清单：

| 样本 | SHA256 |
|------|--------|
| `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` | `54ff62eff26af588782e066b7b3b1b952bc83e1b75a84d81f9492e654cb5c319` |
| `CA_sysmon_hashdump_cmd_meterpreter.evtx` | `897206ca4c3c427753fde880970048494cd5a99be9aaba6154b4e3ac499e24c9` |
| `LM_WMI_4624_4688_TargetHost.evtx` | `3ff3fcdb55c08ec0eaa39b25c1e02a205314f367bcedc662586bd063185ca41d` |
| `LM_Remote_Service02_7045.evtx` | `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458` |
| `sysmon_20_21_1_CommandLineEventConsumer.evtx` | `136cd2549e4944e66c6f26aabafea84011ba011982ac1cf35cde7cb52d32b358` |
| `DE_104_system_log_cleared.evtx` | `5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af` |
| `UACME_59_Sysmon.evtx` | `1de3775180143fd5d956bae48f572367534ae8c10f6ffbe98dd4b4e0e47e0fa1` |

运行命令：

```bash
python3 bla_cli.py /tmp/bla-evtx-real-data-api-db8068 \
  --profile cn-hvv \
  --no-color \
  --max-alerts 12 \
  --exit-on none \
  --out /tmp/bla-evtx-real-review-api-db8068/after
```

最终结果：

| 指标 | 结果 |
|------|-----:|
| 文件 | 7 |
| 解析事件 | 49 |
| 告警 | 9 |
| Incident | 5 |
| 风险 | `100/critical` |
| IOC | 85 |

逐条复查结论：

| 检查项 | 修复前 | 修复后 | 结论 |
|--------|--------|--------|------|
| UACME 样本中的 Sysmon 10 `cmd.exe` / `explorer.exe` / `taskmgr.exe` 进程访问 | 事件级误标 `T1003.001` / `lsass` | 降为普通 `sysmon,process-access`，无凭据访问标签 | 修复误标，不再把非 LSASS 目标当凭据转储 |
| `PowerShell_4104_MiniDumpWriteDump_Lsass` | 仅中危 PowerShell 执行 `T1059.001` | 严重 `T1003.001`，标签 `credential-access` / `credential-dump` / `lsass-dump` | 修复 LSASS dump 漏识别 |
| Sysmon WMI `19/20/21` Event Filter / Consumer / Binding | `事件 ID 19/20/21` 信息级，无持久化语义 | `T1546.003`，创建动作为高危 `wmi-persistence` | 修复 WMI 事件订阅持久化语义 |
| WMIC `root\subscription ... DELETE` | 初版修复中曾被计入持久化创建 | 仅保留 WMI 订阅变更，不进入 `PERS-005` | 避免把清理/删除动作误当创建 |
| `LM_WMI_4624_4688_TargetHost` | 仅展示远程 4624 与进程创建，无横向移动告警 | 新增 `LAT-003 WMI 远程执行链`，关联 5 条事件 | 修复 WMI 横向移动链路漏报 |

新增或变化的告警：

| 告警 | 技术 | 说明 |
|------|------|------|
| `PERS-005 WMI 事件订阅持久化` | `T1546.003` | 只统计 WMI Event Filter/Consumer/Binding 创建及 WMIC CREATE 命令 |
| `LAT-003 WMI 远程执行链` | `T1047` | 网络登录后 2 分钟内出现 WMI 进程执行，置信度 medium |
| `CRED-001` / `CRED-002` | `T1003.001` | 纳入 PowerShell 4104 MiniDumpWriteDump + lsass 脚本块 |

剩余观察：

- `UACME_59_Sysmon.evtx` 目前不再误标凭据访问，但仍未专门定性为 UAC bypass。仅凭这些 Sysmon 10/1 事件缺少足够上下文，后续应结合更完整的 UAC registry/file/process 样本再做通用提权检测。
- Sysmon 10 非 LSASS 进程访问保留为中危过程证据，避免完全丢失进程访问行为，同时不进入凭据访问告警。

## 1. SecRepo Linux auth.log

运行命令：

```bash
python3 bla_cli.py /tmp/bla-hvv-real-data-rAgDex/auth.log \
  --syslog-year 2015 \
  --no-color \
  --max-alerts 5 \
  --exit-on none \
  --out /tmp/bla-real-review-rAgDex/auth/report
```

最终结果：

| 指标 | 结果 |
|------|-----:|
| 原始行数 | 86,839 |
| 解析事件 | 14,825 |
| 告警 | 447 |
| Incident | 30 |
| 风险 | `100/critical` |
| IOC | 641 |

识别情况：

| 检查项 | 原始命中 | BLA 保留 | 结论 |
|--------|---------:|---------:|------|
| `Invalid user ... from IP` | 12,250 | 12,250 | 保留为 SSH 登录失败 |
| `input_userauth_request: invalid user ... [preauth]` | 12,250 | 0 | 过滤为无来源重复噪声 |
| `Too many authentication failures` | 2,575 | 2,575 | 识别为 `认证失败次数过多` |
| 无来源 `failed-login` 聚合事件 | - | 0 | 已消除 |

修复点：

- `linux_auth` parser 过滤无来源的 `input_userauth_request: invalid user` preauth 重复行。
- `Too many authentication failures` 先于泛化失败登录判断，输出 `lockout` / `T1110` 事件。

剩余观察：

- `reverse mapping ... POSSIBLE BREAK-IN ATTEMPT` 在该样本中大量出现，但多与后续 `Invalid user ... from IP` 同源，当前不单独升告警，避免重复放大噪声。

## 2. SecRepo Web access.log

运行命令：

```bash
python3 bla_cli.py /tmp/bla-hvv-real-data-rAgDex/access.log \
  --profile cn-hvv \
  --no-color \
  --max-alerts 5 \
  --exit-on none \
  --out /tmp/bla-real-review-rAgDex/access/report
```

最终结果：

| 指标 | 结果 |
|------|-----:|
| 原始行数 | 2,928 |
| 解析事件 | 142 |
| 告警 | 5 |
| Incident | 2 |
| 风险 | `100/critical` |
| IOC | 64 |

识别情况：

| 检查项 | 原始命中 | BLA 保留 | 结论 |
|--------|---------:|---------:|------|
| `wp-login.php` | 118 | 118 | 保留为敏感文件探测 |
| `wp-admin` | 12 | 12 | 保留为敏感文件探测 |
| `python-requests` | 7 | 7 | 保留为扫描器 |
| `Wget` | 2 | 2 | 保留为扫描器 |
| 普通根路径/静态资源 3xx | 56 | 0 | 过滤为正常跳转/缓存噪声 |
| INFO Web 事件 | - | 0 | 已消除 |

修复点：

- `web_access` parser 过滤无攻击特征的 2xx/3xx 正常响应。
- 敏感路径和扫描器检测先于正常响应过滤，因此 `wp-admin -> 301`、`python-requests -> 200/404` 等攻击线索不丢失。

剩余观察：

- `106.51.67.207` 的 1,403 次访问仍触发 `自动化扫描/高频访问`，这是 volume 行为，不是解析误报。后续如果确认是可信采集或业务访问，应通过 allowlist 或业务基线压制。

## 回归与验证

已运行：

```bash
python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_linux_auth_filters_duplicate_preauth_invalid_user_and_keeps_lockout
python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_web_parser_filters_benign_redirects_without_losing_sensitive_redirect tests/test_parsers.py::ParserRegressionTests::test_web_parser_does_not_flag_browser_ua_or_id_param_as_command tests/test_parsers.py::ParserRegressionTests::test_web_parser_still_detects_command_execution_params
python3 -m pytest -q tests/test_parsers.py
python3 -m compileall -q bla bla_cli.py setup.py tests
python3 -m pytest -q
python3 -m unittest discover -s tests -v
python3 bla_cli.py validate-rules --strict-metadata
python3 scripts/release_check.py
git diff --check
```

结果：

- `tests/test_parsers.py` 43 个用例通过。
- 全量 `pytest` 通过。
- `unittest discover` 202 个测试通过。
- `validate-rules --strict-metadata` 0 error / 0 warning。
- `scripts/release_check.py` 通过。
- `git diff --check` 通过。

## 下一批数据

按同样方式继续逐条过：

1. EVTX-ATTACK-SAMPLES：选 Credential Access、Lateral Movement、Persistence 小样本。
2. Splunk Attack Data：按单技术目录拉取小样本，优先 T1003、T1059、T1071、T1105。
3. OTRF Security-Datasets / Mordor：选择可直接转换的 Windows/Sysmon/JSON 样本。
4. Splunk BOTS v3：先确认导出路径，再做 CSV/JSON 到 P0 JSONL 的转换验证。
