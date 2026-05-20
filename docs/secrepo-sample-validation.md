# SecRepo 公开样本验证记录

本文档记录 BlueTeam Log Analyzer (BLA) 使用 SecRepo 公开日志样本的实际运行方式和结果摘要，用于验证工具在真实日志上的解析、检测、IOC 提取和报告输出能力。

> 说明：SecRepo 样本文件体积较大，且来源为第三方公开数据集，本项目不直接收录原始日志文件。请按下面命令自行下载。

> 结果口径：下方表格是一次历史实测快照，用于说明复现方法和输出形态；新版本可能因为检测窗口、解析器和误报压制优化而产生略有不同的告警数量。

## 数据来源

| 样本 | 地址 | 用途 |
|------|------|------|
| Linux auth.log | https://www.secrepo.com/auth.log/auth.log.gz | SSH 暴力破解、密码喷洒、失败登录聚合、Top IP/Top User |
| Web access.log | https://www.secrepo.com/self.logs/access.log.2017-05-15.gz | Web 敏感路径探测、访问日志解析、IOC 提取、HTML/JSON 报告 |

如果单个文件链接失效，可访问 SecRepo 首页或目录页重新选择样本：

- https://www.secrepo.com/
- https://www.secrepo.com/self.logs/

## 环境

```bash
python3 --version
python3 bla_cli.py --help
```

BLA 仅依赖 Python 3.9+ 标准库。下面的命令在 macOS/Linux Shell 中执行；Windows 用户可用 PowerShell 下载后将路径替换为本地文件路径。

## 实测一：Linux auth.log

### 下载样本

```bash
mkdir -p /tmp/bla-secrepo
curl -L -o /tmp/bla-secrepo/auth.log.gz https://www.secrepo.com/auth.log/auth.log.gz
gunzip -f /tmp/bla-secrepo/auth.log.gz
wc -l /tmp/bla-secrepo/auth.log
```

本次测试样本规模：

```text
86839 /tmp/bla-secrepo/auth.log
```

### 运行 BLA

```bash
python3 bla_cli.py /tmp/bla-secrepo/auth.log \
  --syslog-year 2015 \
  --max-alerts 10 \
  --html /tmp/bla-secrepo/auth_report.html \
  --json /tmp/bla-secrepo/auth_report.json \
  --ioc /tmp/bla-secrepo/auth_iocs.txt \
  --no-color
```

> 发现严重告警时 BLA 会返回退出码 `1`，这是用于自动化告警的预期行为，不代表程序运行失败。

### 结果摘要

| 指标 | 结果 |
|------|------|
| 原始日志行数 | 86,839 |
| 成功解析事件 | 27,075 |
| 综合风险评分 | 100/100（严重） |
| 告警数量 | 624 |
| 严重事件 | 8,825 |
| 高危事件 | 1,523 |
| 中危事件 | 16,727 |
| 时间范围 | 2015-11-30 08:42:04 ~ 2015-12-31 22:27:48 |
| ATT&CK 阶段 | 凭据访问 |
| ATT&CK 技术 | T1110.001, T1110.003 |

Top 攻击源 IP：

| IP | 次数 |
|----|------|
| 220.99.93.50 | 409 |
| 218.25.17.234 | 409 |
| 61.197.203.243 | 409 |
| 188.87.35.25 | 409 |
| 123.57.51.31 | 360 |

Top 目标用户：

| 用户 | 次数 |
|------|------|
| admin | 3,878 |
| root | 2,575 |
| test | 1,866 |
| guest | 1,030 |
| oracle | 898 |

IOC 提取结果：

| IOC 类型 | 数量 |
|----------|------|
| IP | 1,370 |
| 域名 | 1 |
| 用户 | 543 |

本样本主要验证能力：

- Linux auth.log 自动识别与解析
- SSH 暴力破解聚合
- 密码喷洒/多账户尝试识别
- Top IP、Top User、攻击时间范围统计
- `--syslog-year` 历史日志年份补齐
- `--max-alerts` 大型日志终端输出限制
- HTML、JSON、IOC 多格式报告输出

## 实测二：Web access.log

### 下载样本

```bash
mkdir -p /tmp/bla-secrepo/web
curl -L -o /tmp/bla-secrepo/web/access.log.gz https://www.secrepo.com/self.logs/access.log.2017-05-15.gz
gunzip -f /tmp/bla-secrepo/web/access.log.gz
wc -l /tmp/bla-secrepo/web/access.log
```

本次测试样本规模：

```text
2928 /tmp/bla-secrepo/web/access.log
```

### 运行 BLA

```bash
python3 bla_cli.py /tmp/bla-secrepo/web/access.log \
  --profile cn-hvv \
  --html /tmp/bla-secrepo/web_report.html \
  --json /tmp/bla-secrepo/web_report.json \
  --ioc /tmp/bla-secrepo/web_iocs.txt \
  --no-color
```

### 结果摘要

| 指标 | 结果 |
|------|------|
| 原始日志行数 | 2,928 |
| 成功解析事件 | 236 |
| 综合风险评分 | 100/100（严重） |
| 告警数量 | 2 |
| 严重事件 | 1 |
| 中危事件 | 130 |
| 低危事件 | 2 |
| 信息事件 | 103 |
| 时间范围 | 2017-05-15 02:26:52 ~ 2017-05-16 01:54:44 |
| ATT&CK 阶段 | 侦察、初始访问 |
| ATT&CK 技术 | T1083, T1190 |

主要告警：

| 规则 | 等级 | 说明 |
|------|------|------|
| WEB-敏感文件 | 高危 | 检测到 130 次敏感文件探测 |
| RECON-002 | 中危 | 检测到 132 次敏感文件/路径探测 |

Top 攻击源 IP：

| IP | 次数 |
|----|------|
| 52.168.161.70 | 18 |
| 120.192.95.88 | 8 |
| 159.226.251.229 | 7 |
| 103.55.246.20 | 7 |
| 66.247.207.108 | 7 |

IOC 提取结果：

| IOC 类型 | 数量 |
|----------|------|
| IP | 91 |
| 域名 | 14 |
| URL | 13 |
| 文件路径 | 29 |

本样本主要验证能力：

- Apache/Nginx Combined 风格访问日志解析
- 敏感路径和 Web 入口探测识别
- `--profile cn-hvv` 护网/重保增强画像接入
- URL、路径、IP、域名 IOC 提取
- HTML 报告离线生成
- JSON 报告便于二次处理
