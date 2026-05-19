# BLA 测试资源推荐清单

这份清单用于评估 BlueTeam Log Analyzer (BLA) 的解析、检测、IOC 提取、攻击链和报告输出能力，可作为人工验证和回归测试样本来源。

## Windows 事件日志

### EVTX-ATTACK-SAMPLES

- 地址：https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- 类型：Windows EVTX 攻击样本
- 适合验证：凭据访问、权限提升、防御规避、横向移动、Sysmon 事件、PowerShell 事件
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
