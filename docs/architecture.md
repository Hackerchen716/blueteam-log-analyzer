# BLA 可持续迭代架构

BLA 的核心边界是“离线优先的应急分析内核”，不是单个脚本，也不是一开始就做成重型 SIEM。后续新增 Remote Collector、Host Triage、厂商日志适配、Web UI 时，都应围绕同一条稳定管线扩展：

```text
input/source -> parser registry -> enrichment -> allowlist -> detector registry -> correlation -> outputs
```

## 分层边界

| 层 | 目录 | 职责 | 不该做 |
|---|---|---|---|
| CLI | `bla_cli.py`, future `bla/cli/` | 参数解析、子命令分发、退出码 | 不直接写解析/检测规则 |
| Pipeline | `bla/core/pipeline.py` | 编排 parse/enrich/allowlist/detect/output | 不绑定终端交互或 SSH |
| Parser Registry | `bla/parsers/` | 把文件或内存日志块转成 `LogEvent` | 不做跨事件聚合判断 |
| Enrichment | `bla/detection/enrichment.py` | 归一化 `source_type/src_ip/asset/account/event_family` | 不生成告警 |
| Detector Registry | `bla/detection/` | 聚合事件并生成 `DetectionAlert` | 不读取文件、不格式化报告 |
| Correlation | `bla/detection/correlation.py` | 把 alerts/events 合成 incident | 不改写原始事件 |
| Output | `bla/output/` | HTML/JSON/CSV/IOC/SARIF/bundle | 不重新执行检测逻辑 |
| Collector/Triage | future `bla/collectors/`, `bla/triage/` | 只读采集和主机排查 | 不允许任意命令或自动修复 |

## 扩展规则

新增日志源时，优先新增一个 parser 并注册到 `ParserRegistry`，不要改 CLI。解析器必须支持：

- `can_parse(context)`：只做轻量判断；
- `parse_file(context)`：文件路径输入；
- `parse_content(context)`：可选，给 Remote Collector / tests 复用；
- 返回统一 `ParseResult`，事件字段尽量走 `details` 稳定键。

新增检测能力时，优先新增 detector 并注册到 `DetectorRegistry`。Detector 只接收 `List[LogEvent]`，只返回 `List[DetectionAlert]`，不要读取文件、不要写报告。

## 近期演进顺序

1. 继续保持 `bla <path>` 兼容，同时逐步增加 `bla analyze` 这类清晰子命令。
2. #5 Remote Collector 先输出内存日志块，调用 `parse_content()` 或 pipeline，不复制 CLI 逻辑。
3. #8 Host Triage 先定义 `TriageFinding`，独立输出 JSON/HTML，再与 incident 关联。
4. P0 厂商日志适配逐步拆到适配器层，避免 `p0_security.py` 持续膨胀。
5. 大文件方向优先补 Windows XML、CSV、JSON 数组的流式路径。

## Python 是否撑得住

Python 可以撑住 BLA 当前定位：离线 CLI、应急报告、规则匹配、轻量采集和本地工作台都适合 Python。真正需要控制的是架构和数据量：

- 大日志不能总是整文件读入；
- detector 不能无限多轮全表扫描；
- regex 规则要做预筛和基准；
- 远程/主机能力必须只读、白名单、可审计；
- 对 CPU 密集型任务，后续可引入进程池或可选 native/RE2/Hyperscan 后端。

结论：不要因为“以后可能很大”就现在重写语言；先把注册表、pipeline、上下文和样本回归做好，Python 足够把 2.x 的产品形态撑起来。
