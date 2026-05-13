# BLA 架构说明

本文记录 BlueTeam Log Analyzer 在 v1.2.0 之后的主要架构边界。目标是在保持现有 CLI 用法兼容的前提下，让解析器、检测器、远程采集、主机排查和报告输出可以持续迭代。

## 主流程

```text
input/source
  -> parser registry
  -> enrichment
  -> allowlist
  -> detector registry
  -> correlation
  -> outputs
```

## 分层职责

| 层 | 目录 | 职责 | 边界 |
|---|---|---|---|
| CLI | `bla_cli.py`, future `bla/cli/` | 参数解析、子命令分发、退出码 | 不直接实现解析规则和检测规则 |
| Pipeline | `bla/core/pipeline.py` | 编排解析、富化、白名单、检测、关联和输出 | 不绑定终端交互、SSH 或具体 UI |
| Parser Registry | `bla/parsers/` | 将文件或内存日志内容转换为 `LogEvent` | 不做跨事件聚合判断 |
| Enrichment | `bla/detection/enrichment.py` | 归一化 `source_type`、`src_ip`、`asset`、`account`、`event_family` 等字段 | 不生成告警 |
| Detector Registry | `bla/detection/` | 聚合事件并生成 `DetectionAlert` | 不读取文件，不生成报告 |
| Correlation | `bla/detection/correlation.py` | 将 alerts/events 关联成 incident | 不改写原始事件 |
| Output | `bla/output/` | 生成 HTML、JSON、CSV、IOC、SARIF 和 bundle | 不重新执行检测逻辑 |
| Remote Workspace | `bla/remote/` | 通过 SSH 打开远程日志工作台，并把远程输入拉回本机分析 | 目标机不安装 Python/pip/BLA，不开放任意命令 |
| Collector/Triage | future `bla/collectors/`, `bla/triage/` | 只读采集和主机排查 | 不执行自动修复，不允许任意命令 |

## 扩展约定

新增日志源时，优先新增 parser 并注册到 `ParserRegistry`，不要修改 CLI 主流程。解析器应支持：

- `can_parse(context)`：轻量判断是否适配；
- `parse_file(context)`：处理文件路径输入；
- `parse_content(context)`：处理内存日志内容，供 Remote Collector 和测试复用；
- 返回统一 `ParseResult`，事件扩展字段尽量写入稳定的 `details` 键。

新增检测能力时，优先新增 detector 并注册到 `DetectorRegistry`。Detector 只接收 `List[LogEvent]`，只返回 `List[DetectionAlert]`，不读取文件、不写报告、不依赖 CLI 参数解析。

## 后续演进

1. 保持 `bla <path>` 兼容，同时逐步增加更清晰的子命令入口。
2. Remote Workspace 先提供 `bla ssh` 交互入口，远程只执行白名单只读命令，本地复用 pipeline。
3. Remote Collector 输出内存日志内容，复用 `parse_content()` 或 pipeline。
4. Host Triage 独立定义结构化 findings，再与 incident 关联。
5. P0 厂商日志逐步拆分到 adapter 层，避免单个解析器持续膨胀。
6. 大文件场景优先补齐 Windows XML、CSV、JSON 数组等流式处理路径。

## Python 适用边界

Python 适合 BLA 当前阶段的核心能力：离线 CLI、日志解析、规则匹配、应急报告、轻量采集和本地工作台。后续需要重点控制：

- 大日志不能总是整文件读入；
- detector 不应进行过多轮全量扫描；
- regex 规则需要预筛、校验和基准测试；
- 远程采集和主机排查必须只读、白名单、可审计；
- CPU 密集型能力可在后续通过进程池或可选 native/RE2/Hyperscan 后端增强。

在注册表、pipeline、执行上下文和样本回归稳定的前提下，Python 足够支撑 BLA 2.x 阶段的核心产品形态。
