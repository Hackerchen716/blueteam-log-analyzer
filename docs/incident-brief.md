# 应急研判摘要

`incident_brief` 是 BLA 的研判层输出。它不是 `events.csv` 的替代格式，也不是自动定案器；它把解析事件和检测告警压缩成一份可交付、可审计、带证据边界的应急研判。

## 目标

- 让一线值守先看到案情判断，而不是先翻上万行事件明细。
- 把确认事实、研判假设、不能确认项和补证建议分开。
- 把攻击路径拆成有证据边界的 `attack_paths`，明确路径数量、入口候选、文件候选和来源 IP。
- 让 HTML、JSON、Markdown 和终端输出共享同一份研判结构。
- 保留证据引用，方便回到原始日志、`report.json` 或 `events.csv` 复核。
- 面向人工阅读时使用中文时间表达，同时在 JSON 中保留原始时间字段。

## 生成方式

标准报告目录会自动生成研判摘要：

```bash
bla logs/ --out report/ --exit-on none
```

输出文件：

```text
report/incident_brief.md
report/incident_evidence.csv
report/report.json
report/index.html
report/manifest.json
```

`manifest.json` 会记录 `incident_brief.md` 和 `incident_evidence.csv` 的输出哈希，便于交付复核和归档。

只导出 Markdown：

```bash
bla logs/ --brief incident_brief.md --evidence-csv incident_evidence.csv --exit-on none
```

`incident_evidence.csv` 只导出研判摘要实际引用到的证据，用来回答“这个判断依据哪几条日志”。完整事件流水仍在 `events.csv`，但日常研判优先看 `incident_brief.md` 和 `incident_evidence.csv`。

证据包核心列：

- `used_by`：这条证据支撑报告里的哪个事实、发现、假设或攻击路径。
- `timestamp` / `timestamp_text`：原始时间和面向人工阅读的时间。
- `source` / `source_type`：来自哪个日志文件和解析类型。
- `actor_ip`、`method`、`path`、`status`：Web 场景下最常用的回溯字段。
- `raw`：被截断/清洗后的原始日志或消息文本。

从已有 JSON 报告重新渲染：

```bash
bla explain brief --report report/report.json --format markdown
```

## 结构

`report.json` 中的字段为：

```json
{
  "incident_brief": {
    "headline": {},
    "confirmed_facts": [],
    "findings": [],
    "hypotheses": [],
    "key_timeline": [],
    "attack_paths": [],
    "suspected_artifacts": [],
    "actor_profiles": [],
    "uncertainties": [],
    "next_evidence": [],
    "evidence_boundary": {}
  }
}
```

## 研判边界

BLA 只基于当前输入日志输出研判：

- 可以确认：日志中实际出现过的时间、IP、请求、状态码、告警命中和原始证据。
- 可以高置信推断：上传目录脚本文件成功 GET/POST、后台文件管理接口与疑似 Webshell 行为相邻等。
- 不应直接确认：具体 CVE、真实操作者身份、文件真实写入时间、系统命令执行结果、数据外传结果。
- 必须提示补证：认证日志、应用审计、Web 目录文件时间戳和哈希、EDR 进程树、数据库和网络连接记录。

## Web 场景说明

Web access 日志通常会过滤普通成功请求以控制报告规模。研判层需要少量基线证据，因此 BLA 会保留以下成功请求：

- 首页访问：`GET /`
- 登录/认证相关路径
- 上传目录、上传 API、文件管理接口相关路径

普通后台页面成功访问不会全量保留；包含漏洞利用、上传或文件管理语义的后台请求仍会进入事件和研判。

普通静态资源成功请求仍会过滤，例如：

```text
GET /static/app.js -> 200
```

这能避免用户重新回到大 CSV，同时让报告能讲清“什么时候开始访问站点、什么时候进入后台/上传/文件管理相关阶段”。

## 输出使用建议

- 先看 `incident_brief.md` 或 HTML 的“应急研判摘要”。
- 用 `incident_evidence.csv` 回查每条判断引用的原始证据。
- 再看 `report.json["incident_brief"]` 做系统集成或自动化流转。
- Markdown/HTML 只展示关键证据引用，避免重新制造大表格；需要完整复核时，再打开 `report.json`、`events.csv` 或原始日志。
- 汇报时保留“不能确认 / 风险边界”，避免把推断写成已验证事实。
