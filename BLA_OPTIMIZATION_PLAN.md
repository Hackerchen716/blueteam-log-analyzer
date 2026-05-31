# BLA Optimization Plan

## 2026-05-31 - EDR Excel Export Parser and Fake Software Chain Detection

### 本轮目标
- 验证用户提供的 EDR 导出 Excel 样本是否暴露真实兼容性缺口。
- 在不硬编码题目答案、不引入联网查询的前提下，支持 EDR/XDR Excel 进程事件导出。
- 将用户目录无签名伪装进程、临时目录投放、随机名可执行文件、WebRoot 可执行文件、随机计划任务删除、随机目录 ACL 修改和 portproxy reset 作为通用 EDR 关键线索输出，并保持回归覆盖。

### 涉及模块
- `bla/parsers/edr_xlsx.py`
- `bla/parsers/__init__.py`
- `bla/detection/engine.py`
- `bla/detection/enrichment.py`
- `bla/detection/evidence.py`
- `bla/detection/correlation.py`
- `bla/output/terminal.py`
- `scripts/release_check.py`
- `tests/_support.py`
- `tests/test_parsers.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 不把样本文件加入仓库，不记录题目答案或病毒家族名，不依赖 VirusTotal/沙箱/外部情报。
- Parser 只把 Excel 行转为 `LogEvent`，Detector 仍通过既有 P0 EDR detector 生成 `DetectionAlert`。
- XLSX 解析使用标准库 ZIP/XML 流式读取 worksheet，避免把整个工作表读成文本；shared strings 会被截断到单元格长度上限。
- 不改变 remote 行为，不引入默认联网分析，不上传日志。
- 对远程线程事件收紧：只有叠加无签名/用户目录/随机名/投放等信号才升为高危，普通观察项为中危，降低误报。
- 对安全组件 DLL 加载降噪：`Guangzhou TEC Solutions Co., Ltd.` 等常见终端管控/Hook 组件只作为上下文，不单独作为高危核心证据。

### 验证命令
- `python3 bla_cli.py '/Users/chenjianfang/Downloads/日志查询 20260204_171209.xlsx' --no-color --max-alerts 10 --exit-on none`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_edr_xlsx_auto_parse_detects_unsigned_fake_software_chain tests/test_parsers.py::ParserRegressionTests::test_edr_xlsx_content_parser_supports_tsv_rows tests/test_detection.py::DetectionRegressionTests::test_detector_registry_selector_limits_candidate_events tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_edr_vendor_detection_fields_detect_credential_dumping`
- `python3 -m pytest -q tests/test_parsers.py tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- 已复现真实缺口：`日志查询 20260204_171209.xlsx` 在修复前识别为 `通用日志`，解析 ZIP/XML 文本片段，输出 6106 个信息级事件、0 告警。
- 新增 `edr-xlsx` parser，通过 ParserRegistry 注册，支持 `auto_parse()`、显式 `--type edr-xlsx` 和 `parse_content()` 处理 TSV/CSV 文本。
- XLSX 文件解析使用标准库 `zipfile` + `ElementTree.iterparse()` 流式读取 worksheet 行，避免把整个 `.xlsx` 当普通文本或整表读入内存。
- EDR Excel parser 将进程事件字段归一为 `LogEvent`，保留进程名、进程路径、签名、SHA1、目标文件路径、目标签名、文件 SHA1、命令行、行号等证据字段。
- 新增通用启发式：用户目录无签名伪装进程、临时目录投放、随机名可执行文件、WebRoot 可执行文件、随机计划任务删除、随机目录 ACL 修改、用户解压可疑安装目录和 portproxy reset 补采线索；未写入题目答案或病毒家族名。
- 收紧误报：品牌伪装必须同时满足用户目录可执行文件和无签名；远程线程事件只有叠加无签名/用户目录/随机名/投放等信号才升为高危。
- `T1036`、`T1053.005`、`T1055`、`T1204`、`T1222.001` 补充响应阶段映射，EDR Excel 样本的 P0 EDR 告警阶段为“执行”，攻击链分为“执行”“防御规避”和“网络活动”。
- 终端报告新增 EDR 进程链树状展示，并将 EDR 时间线改为多行字段展示，避免长路径和命令行挤在同一行。
- README、`docs/releases/v1.4.4.md`、`docs/testing-resources.md`、`docs/real-data-validation-report.md` 已记录 EDR Excel 支持和本地样本验证结果。
- `scripts/release_check.py` 已纳入 `edr_xlsx.py` 发布面检查、wheel/sdist 包内容检查和安装后 `edr-xlsx` smoke。

### 剩余问题
- 真实样本复跑通过：`EDR Excel Export`、8737 事件、22 高危、39 中危、1 个 `P0-EDR-001` 告警、1 个 incident；原始样本不入仓，仅记录 SHA256 `7753269849198d3da3998968e6c97d043f2c63f6a2a73c46a08e32acc4a9e321`。
- EDR 定点回归通过：覆盖伪装安装包链、SYSTEM 级清理/ACL/portproxy 线索、EDR TSV 解析和终端树状输出。
- Parser/output/detection 回归通过：`python3 -m pytest -q tests/test_parsers.py tests/test_outputs.py tests/test_detection.py`。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，228 个 pytest 用例通过。
- `python3 -m unittest discover -s tests -v` 通过，228 个 unittest 用例通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式、0 errors、0 warnings。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke 和历史版本 smoke。
- `python3 scripts/release_check.py --build` 通过，重新构建 `dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl` 与 `dist/blueteam_log_analyzer-1.4.4.tar.gz`，并通过 `twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI JSON/bundle/manifest smoke、同名输入 manifest smoke、manifest options path smoke 和 `edr-xlsx` smoke。
- `git diff --check` 通过。
- 尚未发布：未 commit、未 push、未 tag、未上传 PyPI、未创建 GitHub Release；发布前仍需用户最终确认。

## 2026-05-30 - v1.4.4 Release Candidate External and Artifact Audit

### 本轮目标
- 在不执行发布动作的前提下，补强 v1.4.4 发布候选的外部状态、构建产物和关键入口审计证据。
- 确认 GitHub Release、Git tag 和 PyPI 仍停留在 v1.4.3，避免重复发布或覆盖既有版本。
- 抽检 wheel/sdist 内容，确认 v1.4.4 构建产物包含新增 parser、CLI 入口、离线资产、发布说明和 release gate。

### 涉及模块
- `BLA_OPTIMIZATION_PLAN.md`
- `dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl`
- `dist/blueteam_log_analyzer-1.4.4.tar.gz`
- 外部发布面：origin tags、PyPI JSON、GitHub Release

### 风险边界
- 本轮只读审计外部状态和本地构建产物，不 commit、不 push、不 tag、不上传 PyPI、不创建 GitHub Release。
- 不改 parser/detector/correlation/output/remote runtime 逻辑。
- 网络访问仅用于读取 PyPI/GitHub 当前发布状态，不上传日志或分析数据。

### 验证命令
- `git status --short`
- `git ls-remote --tags --refs origin 'refs/tags/v1.4.4' 'refs/tags/v1.4.3'`
- `python3 -c 'import json, urllib.request; ... https://pypi.org/pypi/blueteam-log-analyzer/json ...'`
- `gh release view v1.4.4 --repo Hackerchen716/blueteam-log-analyzer --json tagName,name,url,publishedAt,isDraft,isPrerelease 2>&1 || true`
- `gh release view --repo Hackerchen716/blueteam-log-analyzer --json tagName,name,url,publishedAt,isDraft,isPrerelease 2>&1 || true`
- `python3 -m zipfile -l dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl | rg 'windows_json.py|bla/cli/main.py|web_attacks.yaml|world-countries.geojson|METADATA|entry_points.txt'`
- `tar -tf dist/blueteam_log_analyzer-1.4.4.tar.gz | rg 'docs/releases/v1\.4\.4\.md|scripts/release_check.py|tests/test_parsers.py|bla/parsers/windows_json.py|README.md'`
- `unzip -p dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl blueteam_log_analyzer-1.4.4.dist-info/METADATA | sed -n '1,80p'`
- `unzip -p dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl blueteam_log_analyzer-1.4.4.dist-info/entry_points.txt`
- `rg -n "TODO|FIXME|known issue|已知问题|P1|发布失败|release-check failed" BLA_OPTIMIZATION_PLAN.md docs/releases/v1.4.4.md docs/real-data-validation-report.md README.md`
- `git diff --name-status`

### 修改结果
- `git ls-remote` 显示 origin 存在 `refs/tags/v1.4.3`，未返回 `refs/tags/v1.4.4`。
- PyPI 官方 JSON 当前版本为 `1.4.3`，`releases` 中尚无 `1.4.4`。
- `gh release view v1.4.4` 返回 `release not found`；GitHub 当前 latest release 为 `BlueTeam Log Analyzer v1.4.3`，tag `v1.4.3`。
- wheel 内容包含 `bla/parsers/windows_json.py`、`bla/cli/main.py`、`bla/rules/web_attacks.yaml`、`bla/output/assets/world-countries.geojson`、`METADATA` 和 `entry_points.txt`。
- sdist 内容包含 `README.md`、`bla/parsers/windows_json.py`、`docs/releases/v1.4.4.md`、`scripts/release_check.py` 和 `tests/test_parsers.py`。
- wheel metadata 显示 `Name: blueteam-log-analyzer`、`Version: 1.4.4`、`Requires-Python: >=3.9`。
- wheel entry point 显示 `bla = bla.cli.main:main`。

### 剩余问题
- 当前工作区仍是未提交发布候选 diff；这是预期状态，因为正式发布前需要先汇报并等待用户确认。
- 本轮审计未发现 `docs/releases/v1.4.4.md`、README 或真实数据报告中存在 TODO/FIXME/发布失败类标记；搜索到的 `P0/P1` 均为优化计划中“未发现 P0/P1 已知问题”的记录。
- 尚未发布：未 commit、未 push、未 tag、未上传 PyPI、未创建 GitHub Release、未验证 GitHub Release Latest。

## 2026-05-30 - v1.4.4 Release Metadata Preparation

### 本轮目标
- 补齐 v1.4.4 发布前版本面：包版本、README 当前版本说明和 `docs/releases/v1.4.4.md`。
- 确认远端尚未存在 `v1.4.4` tag，避免覆盖已发布版本。
- 运行发布级门禁和构建门禁，完成发布前汇报；本轮不 tag、不 push、不上传、不创建 GitHub Release。

### 涉及模块
- `bla/__version__.py`
- `README.md`
- `docs/releases/v1.4.4.md`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只做发布元数据和说明更新，不改变 parser/detector/correlation/output/remote 运行逻辑。
- 不引入默认联网行为；HTML 报告仍必须离线可用；远程能力仍保持只读、限量、超时、可审计。
- 不发布、不打 tag、不 push、不上传 PyPI；正式发布前先向用户汇报并等待确认。
- 发布说明只概括已由测试覆盖的能力变化，避免把样本特征写成硬编码承诺。

### 验证命令
- `git ls-remote --tags --refs origin 'refs/tags/v1.4.4' 'refs/tags/v1.4.3'`
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_version_surfaces_are_consistent tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- 远端 tag 检查显示 origin 只有 `v1.4.3`，尚无 `v1.4.4`。
- `bla/__version__.py` 已更新为 `1.4.4`，`python3 bla_cli.py --version` 输出 `BLA 1.4.4`。
- README 当前版本区已更新为 `v1.4.4`，概括 Windows JSON、Windows XML/EVTX、检测质量、输出安全、manifest 和 release gate 变化。
- 新增 `docs/releases/v1.4.4.md`，记录主要变化、使用方式、安全边界和验证命令。
- `python3 scripts/release_check.py --build` 已构建本地 `dist/blueteam_log_analyzer-1.4.4-py3-none-any.whl` 与 `dist/blueteam_log_analyzer-1.4.4.tar.gz`，并通过 `twine check` 与离线安装后 smoke。

### 剩余问题
- 定点 release hygiene 回归通过：`2 passed`。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，224 个 pytest 用例通过。
- `python3 -m unittest discover -s tests -v` 通过，224 个 unittest 用例通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式、0 errors、0 warnings。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0/v1.4.1/v1.4.2/v1.4.3 smoke。
- `python3 scripts/release_check.py --build` 通过，覆盖本地 wheel/sdist 构建、`twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI JSON smoke、安装后 CLI bundle/manifest smoke、同名输入 manifest smoke 和 manifest options path smoke。
- `git diff --check` 通过。
- 尚未发布：未 commit、未 push、未 tag、未上传 PyPI、未创建 GitHub Release。下一步需要发布前最终汇报和用户确认。

## 2026-05-30 - Release Build Installed CLI Manifest Option Path Smoke

### 本轮目标
- 把 CLI `manifest.options` 路径显示名修复纳入 `scripts/release_check.py --build` 的安装后 wheel smoke。
- 验证构建出的 wheel 安装后，实际 console script `bla --out --config --allowlist --rules` 不会把本地临时绝对路径写入 manifest。
- 继续保持离线安装 smoke，不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变 runtime parser/detector/correlation/output/remote 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- 使用临时目录内合成 config、allowlist、rules 和 access log，不引入第三方样本或网络访问。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `scripts/release_check.py --build` 的离线安装后 smoke 现在会创建 `token=super-secret` 临时目录，并在其中生成 `thresholds.json`、`allowlist.json`、`rules-token=super-secret/` 和 `access.log`。
- 安装后 smoke 会通过已安装的 `bla --out --config --allowlist --rules` 生成 `manifest-options-bundle`。
- 安装后 smoke 会验证 `manifest.options.config == thresholds.json`、`allowlist == allowlist.json`、`rules == [rules-token=<redacted>]`。
- 安装后 smoke 会确认 manifest 不包含临时绝对路径或原始 `super-secret`。
- `tests/test_release_hygiene.py` 现在要求发布脚本保留 manifest options bundle、config 泄漏失败文案和 rules 脱敏标签，避免后续误删。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖完整发布门禁、本地 wheel/sdist 构建、`twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI JSON smoke、安装后 CLI bundle/manifest smoke、安装后 CLI duplicate basename manifest smoke、安装后 CLI manifest options path smoke。
- `git diff --check` 通过。
- 构建产物仍为当前版本号，不改版本号、不 tag、不 push、不上传、不发布。

## 2026-05-30 - CLI Manifest Option Path Redaction

### 本轮目标
- 修复普通 CLI `--out` 生成的 `manifest.options` 记录 `--config` / `--rules` / `--allowlist` 原始本地路径的问题。
- 避免交付 manifest 泄漏操作员本地绝对目录、终端控制字符或明显 secret，同时保留可审计的配置文件/规则目录显示名。
- 继续保持 CLI 只负责参数和命令分发；实际输入 provenance 仍由 pipeline 生成。

### 涉及模块
- `bla/cli/main.py`
- `tests/test_outputs.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只改变 manifest 中 options 的显示值，不改变实际 `--config` / `--rules` / `--allowlist` 加载路径和检测行为。
- 输出层仍会对最终 manifest 做统一递归清洗，本轮是在 CLI context 源头减少路径暴露。
- 不改 parser/detector/correlation/remote，不引入联网行为。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_cli_manifest_options_use_safe_path_labels`
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_cli_manifest_options_use_safe_path_labels tests/test_outputs.py::OutputRegressionTests::test_cli_bundle_manifest_disambiguates_duplicate_basenames`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- 已复现问题：`manifest.options.config` / `allowlist` / `rules` 记录用户传入的原始本地路径，末端 manifest sanitizer 虽会脱敏 secret，但仍保留本地临时目录结构。
- 新增 CLI 级回归，使用带终端控制字符和 `token=super-secret` 的临时目录作为 `--config`、`--allowlist`、`--rules`，断言 manifest 只保留安全显示名。
- CLI `_build_manifest_context()` 现在对 `config`、`allowlist`、`rules`、`geoip_cache` 调用 `_manifest_path_label()` / `_manifest_path_labels()`，只记录 basename 并进行 `sanitize_report_text()`。
- 实际加载路径不变：`run_analysis()` 仍使用原始 `args.config` / `args.rules` / `args.allowlist` 执行配置、规则和白名单加载。

### 剩余问题
- 定点 manifest options 回归通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，37 个输出回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0/v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮不发布；发布前仍需对最新 runtime 改动补跑 `scripts/release_check.py --build` 并完成 v1.4.4 版本号 / release notes / 发布前汇报。

## 2026-05-30 - Release Build Installed CLI Duplicate Basename Manifest Smoke

### 本轮目标
- 把普通 CLI `--out` 同名输入 manifest provenance 修复纳入 `scripts/release_check.py --build` 的安装后 wheel smoke。
- 验证构建出的 wheel 安装后，实际 console script `bla` 对两个不同目录下同名日志也能在 `manifest.inputs` / `parsed_files` 中保留唯一相对标签。
- 继续保持离线安装 smoke，不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变 runtime parser/detector/correlation/output/remote 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- 只使用临时目录内合成 access log，不引入第三方样本或网络访问。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `scripts/release_check.py --build` 的离线安装后 smoke 现在会创建 `duplicate-basenames/host-a/access.log` 与 `duplicate-basenames/host-b/access.log`。
- 安装后 smoke 会通过已安装的 `bla --out` 生成 `duplicate-basenames-bundle`，并验证 `manifest.inputs` 与 `parsed_files` 均保留 `host-a/access.log`、`host-b/access.log`。
- 安装后 smoke 会验证 `summary.files_analyzed == 2`，manifest 不泄漏临时目录绝对路径，并校验两个输入文件的 sha256。
- `tests/test_release_hygiene.py` 现在要求发布脚本保留 duplicate basename bundle、输入标签和 collapse failure 文案，避免后续误删。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖完整发布门禁、本地 wheel/sdist 构建、`twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI JSON smoke、安装后 CLI bundle/manifest smoke、安装后 CLI duplicate basename manifest smoke。
- `git diff --check` 通过。
- 构建产物仍为当前版本号，不改版本号、不 tag、不 push、不上传、不发布。

## 2026-05-30 - CLI Bundle Manifest Duplicate Basename Provenance

### 本轮目标
- 修复普通 CLI `--out` 路径下 `manifest.inputs` 对同名输入文件仍只记录 basename 的问题。
- 避免两个目录下同名日志在交付 manifest 中被误认为同一个输入，同时保持不写绝对路径、不泄漏本地临时目录。
- 降低大文件默认运行成本：没有 `--out` 时，CLI 不再提前构建 manifest context 和计算输入 sha256。

### 涉及模块
- `bla/core/pipeline.py`
- `bla/core/__init__.py`
- `bla/cli/main.py`
- `tests/test_outputs.py`
- `docs/real-data-validation-report.md`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- Parser/detector/correlation/output/remote 行为不变；仅复用 pipeline 输入 provenance 生成逻辑。
- CLI 仍只负责参数解析、命令分发和附加 CLI options 到 manifest context，不重新实现输入哈希与展示名规则。
- sha256 仍按 1 MB chunk 流式读取；只在生成标准报告 bundle 时计算。
- 不改版本号、不 tag、不 push、不上传、不发布。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_cli_bundle_manifest_disambiguates_duplicate_basenames tests/test_outputs.py::OutputRegressionTests::test_run_analysis_bundle_manifest_hashes_local_inputs_without_absolute_paths`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `python3 bla_cli.py benchmark --size-mb 1`
- `python3 bla_cli.py benchmark --size-mb 1 --memory`
- `git diff --check`

### 修改结果
- 已复现问题：两个不同目录下的 `access.log` 经 `bla_cli.py --out` 生成报告后，`manifest.inputs` 只有重复的 `access.log`，而 `parsed_files` 已经是唯一相对标签。
- 新增 CLI 级回归，断言 `manifest.inputs` 和 `manifest.parsed_files` 都使用 `host-a/access.log`、`host-b/access.log`，`summary.files_analyzed == 2`，且不含本地绝对路径。
- `pipeline` 暴露 `build_local_manifest_context()`，统一生成本地输入 provenance、展示名、类型、大小、事件数和 sha256。
- CLI `_build_manifest_context()` 改为复用 pipeline provenance，只附加 CLI options。
- CLI 主流程仅在 `args.out` 存在时构建 manifest context，避免无 bundle 输出时对大输入做额外 sha256 读取。
- `docs/real-data-validation-report.md` 已把同名 basename 压缩项更新为后续已修复说明。

### 剩余问题
- 定点 CLI manifest 回归与 pipeline manifest 回归通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，36 个输出回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，223 个 unittest 用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0/v1.4.1/v1.4.2/v1.4.3 smoke。
- `python3 bla_cli.py benchmark --size-mb 1` 通过：1.00 MB、6,833 事件、44 告警、4 incident、0.508s、1.97 MB/s。
- `python3 bla_cli.py benchmark --size-mb 1 --memory` 通过：1.00 MB、6,833 事件、44 告警、4 incident、1.714s、0.58 MB/s、peak memory 32.95 MB。
- `git diff --check` 通过。
- 本轮不发布。

## 2026-05-30 - Release Build Installed CLI Bundle Manifest Smoke

### 本轮目标
- 增强 `scripts/release_check.py --build`：构建 wheel 后通过安装后的 `bla --out` 生成完整离线报告包。
- 验证安装后 CLI 的 HTML/JSON/CSV/IOC/SARIF/manifest 输出链路、manifest 输入哈希和输出哈希，避免只覆盖单文件 JSON 导出。
- 继续保持离线安装 smoke，不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变 runtime parser/detector/correlation/output/remote 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- HTML 离线校验只检查发布包生成的报告不依赖常见 CDN 域名，不引入联网行为。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `scripts/release_check.py --build` 的离线安装后 smoke 现在会用已安装的 `bla --out` 生成 `installed-cli-bundle`。
- 安装后 bundle smoke 会确认 `index.html`、`report.json`、`events.csv`、`iocs.txt`、`report.sarif`、`manifest.json` 全部存在。
- 安装后 bundle smoke 会确认 bundle JSON 包含 Windows `EventID=4688` 事件。
- 安装后 bundle smoke 会确认 manifest schema、输入记录、输入 `sha256`、非绝对输入路径，以及每个输出文件的 `sha256`。
- 安装后 bundle smoke 会确认 HTML 报告不依赖 `cdn.jsdelivr` / `unpkg.com`。
- `tests/test_release_hygiene.py` 现在要求发布脚本保留 installed CLI bundle、manifest input hash 和 CDN 离线检查。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖完整发布门禁、本地 wheel/sdist 构建、`twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI JSON smoke、安装后 CLI bundle/manifest smoke。
- `git diff --check` 通过。
- 构建产物仍为当前版本号，不改版本号、不 tag、不 push、不上传、不发布。

## 2026-05-30 - Release Build Installed CLI Smoke

### 本轮目标
- 增强 `scripts/release_check.py --build`：构建 wheel 后不仅验证 Python API，也验证安装后的 console script `bla` 可用。
- 覆盖发布包入口点与源码入口不一致的风险，确认用户安装 wheel 后可以直接用 CLI 分析 Windows JSON 文件。
- 继续保持离线安装 smoke，不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变运行时 parser/detector/correlation/output/remote 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `scripts/release_check.py --build` 现在会在本地 wheel 离线安装后解析 installed console script 路径，并执行安装后的 `bla --version`。
- 安装后 CLI smoke 会使用已安装的 `bla` 分析 `winlogbeat-pretty.json`，输出 `installed-cli-report.json`。
- 安装后 CLI smoke 会确认 JSON 报告包含 Windows `EventID=4688` 事件，并保留 `auditpol-tampering` 标签，覆盖“源码能跑但 wheel 安装入口不可用”的发布风险。
- `tests/test_release_hygiene.py` 现在要求发布脚本保留 `_venv_script`、`installed-cli-report.json` 和 installed console script 检查，避免后续误删。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖完整发布门禁、本地 wheel/sdist 构建、`twine check`、离线 wheel 安装、安装后 Python API/content/file smoke、安装后 CLI smoke。
- `git diff --check` 通过。
- 构建产物仍为当前版本号，不改版本号、不 tag、不 push、不上传、不发布。

## 2026-05-30 - Release Build Pretty Windows JSON File Smoke

### 本轮目标
- 把 Windows JSON pretty 文件入口兼容性纳入 `scripts/release_check.py --build` 的安装后 smoke。
- 确认构建出的 wheel 安装后不仅 `parse_content()` 可解析 Winlogbeat JSON，`auto_parse()` 文件入口也能解析格式化 Windows JSON 文件。
- 继续保持离线安装 smoke，不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变运行时 parser/detector 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `release_check.py --build` 的离线安装后 smoke 现在会从构建出的 wheel 安装 BLA，再创建 `winlogbeat-pretty.json`。
- 安装后 smoke 会通过已安装包的 `auto_parse()` 解析该 pretty Windows JSON 文件，确认 `Windows Event Log (JSON)`、`stats.total == 1`、`parse_errors == 0`、`EventID == 4688`。
- 安装后 smoke 会确认 pretty 文件入口解析出的 4688 auditpol 事件保留 `auditpol-tampering` 标签。
- release hygiene 回归要求发布脚本保留 `auto_parse` 与 `winlogbeat-pretty.json` 检查，避免后续误删该文件入口覆盖。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke、wheel/sdist 构建、twine check、发行包内容检查、离线安装后 Windows JSON parser content/file smoke。
- `git diff --check` 通过。
- 本轮未改版本号、未 tag、未 push、未上传、未发布。

## 2026-05-30 - Windows JSON Pretty File Streaming Compatibility

### 本轮目标
- 修复 Windows JSON 文件入口只能稳定处理数组或单行 JSONL、不能处理格式化 pretty JSON 对象/sequence 的问题。
- 让文件入口与 `parse_content()` 的真实日志兼容性保持一致，同时保持流式解析，不整文件读入。
- 继续不发布、不改版本号。

### 涉及模块
- `bla/parsers/windows_json.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- Parser 只负责把 Windows JSON 转为 `LogEvent`，不新增 detector 规则。
- 单行 JSONL 仍优先走逐行解析，保留坏行容错能力。
- pretty JSON 对象/JSON sequence 走 chunk 流式 decoder，不为兼容性牺牲大文件稳定性。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_json_pretty_winlogbeat_file_streams_single_object`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_json_pretty_winlogbeat_file_streams_single_object tests/test_parsers.py::ParserRegressionTests::test_windows_jsonl_file_keeps_partial_events_and_counts_decode_error`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- 已复现问题：同一份 Winlogbeat/Elastic Windows JSON，`parse_content()` 可解析，但格式化 pretty JSON 文件入口解析为 0 事件。
- `parse_windows_json_file()` 对非数组输入增加分流：
  - 第一条非空行是完整 JSON object 时，继续走逐行 JSONL 解析，保留坏行容错。
  - 否则走新增的 chunk 流式 JSON sequence decoder，支持 pretty 单对象和多对象 sequence。
- 新增 `_iter_json_sequence_records_from_chunks()`，按 chunk 增量 `raw_decode`，避免为 pretty JSON 兼容性整文件读入。
- 新增回归测试覆盖 pretty Winlogbeat 文件，确认 4688 auditpol 事件被识别为 Windows JSON 并保留 `auditpol-tampering` / `defense-evasion` 标签。

### 剩余问题
- 定点回归先失败后通过，确认问题真实存在且修复有效。
- 同时复跑 JSONL 坏行容错回归，确认逐行路径未被破坏。
- `python3 -m pytest -q tests/test_parsers.py` 通过，55 个 parser 用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，222 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，222 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - Release Build Winlogbeat Parser Smoke

### 本轮目标
- 把刚新增的 Winlogbeat/Elastic Windows JSON 兼容性纳入 `scripts/release_check.py --build` 的安装后 smoke。
- 避免出现源码测试通过，但构建出的 wheel 安装后只覆盖扁平 OTRF JSON、没有覆盖嵌套 Windows JSON 的发布盲区。
- 继续保持不联网、不发布。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查，不改变运行时 parser/detector 行为。
- 安装 smoke 继续只使用本地 wheel 和 `--no-index`。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `release_check.py --build` 的安装后 smoke 现在同时覆盖：
  - 扁平 Sysmon Windows JSON 事件。
  - 单条坏 JSONL 行后的继续解析。
  - Winlogbeat/Elastic 嵌套 Windows 4688 auditpol 事件。
- 安装后 smoke 会确认构建出的 wheel 安装后仍注册 `windows-json`，并能输出 `EventID=1` 和 `EventID=4688` 两类事件。
- 安装后 smoke 会确认 4688 auditpol 嵌套事件保留 `auditpol-tampering` 标签。
- release hygiene 回归要求发布脚本保留 `winlogbeat_record` 和 `auditpol-tampering` 检查，避免后续误删。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke、wheel/sdist 构建、twine check、发行包内容检查、离线安装后 Windows JSON parser smoke。
- `git diff --check` 通过。
- 本轮未改版本号、未 tag、未 push、未上传、未发布。

## 2026-05-30 - Winlogbeat Windows JSON Field Compatibility

### 本轮目标
- 继续增强 `1.4.4` 的真实 Windows JSON 日志兼容性，不进入发布流程。
- 让 `windows-json` parser 支持 Winlogbeat/Elastic 常见嵌套字段，例如 `winlog.event_id`、`winlog.channel`、`winlog.event_data.*`、`event.code`、`host.name`、`process.command_line`。
- 复用现有 Windows EventLog 分类与 detector，不新增针对固定样本、固定 IP、固定域名或固定用户的规则。

### 涉及模块
- `bla/parsers/windows_json.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- Parser 只做字段归一化并生成 `LogEvent`，不在 parser 层新增 detector 逻辑。
- 只补通用字段别名/嵌套结构，不按文件名、样本仓库路径或 IOC 过拟合。
- 不改变已有 OTRF/Mordor 扁平字段优先级；已有字段不被别名覆盖。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_json_winlogbeat_content_maps_nested_fields_to_existing_classification`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- 已复现问题：Winlogbeat/Elastic 风格 Windows JSONL 会被 `p0-security` 抢先识别，导致 Windows EventLog 分类与现有 detector 规则无法复用。
- `looks_like_windows_event_json()` 增强了通用 Windows JSON 指示器，支持 `winlog`、`winlog.event_id` / `event.code`、`provider_name` 等常见字段。
- `windows-json` parser 新增嵌套字段归一化：
  - `winlog.event_data.*` 展开为 Windows EventData 字段。
  - `winlog.event_id` / `event.code` -> `EventID`。
  - `winlog.channel` -> `Channel`。
  - `winlog.provider_name` / `event.provider` -> `SourceName`。
  - `host.name` / `winlog.computer_name` -> `Hostname` / `Computer`。
  - `process.command_line`、`process.executable`、`process.parent.executable` 映射到现有 Windows/Sysmon 进程字段。
  - `source.*`、`destination.*`、`dns.question.name` 映射到现有网络/DNS 字段。
- 新增回归测试覆盖 Winlogbeat 风格 4688 auditpol 事件，确认它自动进入 `windows-json`，并复用现有 `auditpol-tampering` / `defense-evasion` / `T1562.002` 分类。

### 剩余问题
- 定点回归先失败后通过，确认问题真实存在且修复有效。
- `python3 -m pytest -q tests/test_parsers.py` 通过，54 个 parser 用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，221 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，221 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - Release Build Windows JSON Packaging Smoke

### 本轮目标
- 继续增强 `1.4.4` 发布前质量门禁，不进入发布流程。
- 修复发布检查没有覆盖新增 `windows-json` parser 发行包内容的问题，避免本地测试通过但 wheel/sdist 漏文件。
- 在 `--build` 门禁中增加离线安装 smoke，确认构建出的 wheel 安装后能注册并使用 `windows-json` parser。

### 涉及模块
- `scripts/release_check.py`
- `tests/test_release_hygiene.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强发布检查脚本和回归测试，不改变 CLI/parser/detector/correlation/output/remote 运行时语义。
- 安装 smoke 只使用本地 wheel 和 `--no-index`，不访问网络。
- 不改版本号、不 tag、不 push、不上传。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_release_check_script_and_setup_version_are_safe`
- `python3 scripts/release_check.py --build`
- `git diff --check`

### 修改结果
- `release_check.py --build` 现在把 `bla/parsers/windows_json.py` 纳入 required release surfaces、wheel 内容检查和 sdist 内容检查。
- `release_check.py --build` 构建完成后会创建临时 venv，用本地 wheel 执行 `pip install --no-index`，避免联网。
- 安装后 smoke 会从已安装包导入 `list_parser_names` / `parse_content`，确认 `windows-json` 已注册，并用含坏行的 Windows JSONL 样本验证 `stats.total == 2`、`parse_errors == 1`。
- 更新 release hygiene 回归，要求发布脚本持续包含 `windows_json.py`、安装后 smoke、`--no-index` 和 `windows-json` 检查。

### 剩余问题
- 定点 release hygiene 回归通过。
- `python3 scripts/release_check.py --build` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke、wheel/sdist 构建、twine check、发行包内容检查、离线安装后 Windows JSON parser smoke。
- 构建日志确认 `bla/parsers/windows_json.py` 已写入 sdist 和 wheel。
- `git diff --check` 通过。
- 本轮未改版本号、未 tag、未 push、未上传、未发布。

## 2026-05-30 - Windows JSON Content Partial Error Tolerance

### 本轮目标
- 继续增强 `1.4.4` 发布候选的真实日志兼容性，不进入发布流程。
- 修复 Windows EventLog JSONL 在 ParserRegistry `parse_content` / remote 内存入口中遇到单条坏 JSON 后丢失后续有效记录的问题。
- 与文件入口保持一致：有效记录尽量保留，坏记录计入 `parse_errors`，parser 不新增检测规则。

### 涉及模块
- `bla/parsers/windows_json.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只增强非数组 JSONL/JSON sequence 内容入口的坏行容错；JSON array 内容仍按结构化数组处理。
- 不按固定样本名、固定 IP、固定域名、固定用户写规则，避免过拟合。
- 不改变 detector/correlation/output/remote 边界，不增加联网行为。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_jsonl_content_keeps_partial_events_and_counts_decode_error`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- 已复现问题：同一段 Windows EventLog JSONL 内容经 ParserRegistry `parse_content()` 解析时，坏 JSON 行之后的有效记录会丢失。
- `parse_windows_json()` 现在对非数组 JSONL/JSON sequence 内容在解码失败时跳到下一行继续解析，坏行计入 `parse_errors`。
- JSON array 内容仍保持结构化数组解析语义；数组损坏计为解析错误，不尝试猜测后续结构。
- 新增回归测试覆盖内存内容入口：有效记录、坏 JSON 行、有效记录，确认保留 2 条事件并记录 1 个 parse error。

### 剩余问题
- 定点回归先失败后通过，确认问题真实存在且修复有效。
- `python3 -m pytest -q tests/test_parsers.py` 通过，53 个 parser 用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，220 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，220 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - Local Manifest Input Hash Provenance

### 本轮目标
- 继续增强 `1.4.4` 发布候选的取证可验证性，不进入发布流程。
- 修复本地标准报告 bundle 的 `manifest.inputs` 缺少输入文件 sha256 的问题，使本地 manifest 与 remote manifest 一样可审计。
- 保持输出安全：manifest 中不写入绝对路径，输入名称继续使用报告展示标签。

### 涉及模块
- `bla/core/pipeline.py`
- `tests/_support.py`
- `tests/test_outputs.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 只为本地 `--out` bundle 增加输入 hash provenance，不改变 parser/detector/correlation 语义。
- sha256 按流式读取计算，不整文件读入内存。
- 不增加默认联网，不修改 remote 只读边界。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_run_analysis_bundle_manifest_hashes_local_inputs_without_absolute_paths`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- `run_analysis` 在写标准 bundle 时生成本地 manifest context，输入记录包含展示名、日志类型、大小、事件数和 sha256。
- 输入 sha256 使用 1 MB chunk 流式计算，不整文件读入。
- manifest 继续不包含绝对路径；同名文件仍使用 pipeline 的最短唯一相对展示标签。
- 新增回归测试覆盖本地 `--out` bundle manifest，确认 `inputs[0].sha256` 存在且不泄露临时目录绝对路径。

### 剩余问题
- 定点回归通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，35 个 output 用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，219 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，219 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - v1.4.4 Continuous Release Readiness Goal

### 本轮目标
- 建立 `1.4.4` 发布前持续优化目标：继续多轮、小步、可验证地增强 BLA，而不是因为当前 gate 通过就急于发布。
- 将 `1.4.4` 定位为真实日志兼容性、Windows 攻击样本检测、输出安全、取证溯源和发布可靠性的增强版本。
- 发布前必须先向用户汇报；未经确认不 tag、不 push、不上传、不创建 GitHub Release / PyPI release。

### 涉及模块
- `BLA_OPTIMIZATION_PLAN.md`
- 后续每轮按实际改动覆盖 parser / detector / correlation / output / remote / tests / docs

### 风险边界
- 保持离线优先：不增加默认联网，不让 HTML 依赖 CDN，不上传日志。
- 保持架构边界：CLI 只分发，pipeline 只编排，parser 只产出 `LogEvent`，detector 只产出 `DetectionAlert`，correlation 只关联 incident，output 只生成报告与 manifest，remote 只读、白名单、限量、可审计。
- 不为了真实样本写路径、文件名、固定 IP、固定域名、固定用户的过拟合规则。
- 不做大规模重写；优先修复真实可复现的问题，并为每个修复增加回归测试或 smoke。

### 发布准入条件
- `1.4.4` 版本号、README 当前版本区、`docs/releases/v1.4.4.md` 和发布说明全部一致。
- 完整通过：
  - `python3 -m compileall -q bla bla_cli.py setup.py tests`
  - `python3 -m pytest -q`
  - `python3 -m unittest discover -s tests -v`
  - `python3 bla_cli.py validate-rules --strict-metadata`
  - `python3 scripts/release_check.py`
  - `python3 scripts/release_check.py --build`
  - `git diff --check`
- 涉及性能/大文件路径时额外通过：
  - `python3 bla_cli.py benchmark --size-mb 1`
  - `python3 bla_cli.py benchmark --size-mb 1 --memory`
- 工作树 diff 经最终人工复核，确认没有无关重写、没有破坏 remote 安全边界、没有引入默认联网。
- 发布前向用户提交正式发布汇报，得到确认后再进入 commit/tag/GitHub Release/PyPI 流程。

### 修改结果
- 已建立持续目标：继续优化到 `1.4.4` 满足发布准入条件为止。
- 当前仍不发布；后续继续按真实问题逐条改进。

### 剩余问题
- 下一轮优先检查 manifest/input provenance 与同名文件展示标签的一致性。
- 后续继续检查 Windows JSON/EVTX 坏字段容错、Sysmon 噪声边界、真实样本漏报/误报和 release notes 完整性。

## 2026-05-30 - Windows JSONL Partial Parse Error Tolerance

### 本轮目标
- 继续增加 `1.4.4` 的真实日志稳健性，不进入发布流程。
- 修复 Windows EventLog JSONL 文件中单行损坏会中断后续有效记录解析的问题。
- 保持大文件友好：继续逐行流式解析 JSONL，不为容错改成整文件读入。

### 涉及模块
- `bla/parsers/windows_json.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 仅对 JSONL/JSON sequence 风格文件增强逐行容错；JSON array 仍按结构化数组处理，数组整体损坏继续计为解析错误。
- Parser 只负责保留有效 Windows EventLog 记录并统计 `parse_errors`，不新增 detector 规则。
- 不基于样本文件名、固定字段值、固定用户或固定域名做判断。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_jsonl_file_keeps_partial_events_and_counts_decode_error`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- Windows JSONL 文件解析改为逐行独立 `json.loads`；单行损坏时递增 `parse_errors` 并继续处理后续有效记录。
- JSON array 仍走增量 chunk decoder，保持结构化数组的整体语义和大文件友好特性。
- 新增回归测试覆盖有效记录、坏 JSON 行、有效记录的组合，确认保留 2 条事件并记录 1 个 parse error。

### 剩余问题
- 定点回归通过。
- `python3 -m pytest -q tests/test_parsers.py` 通过，52 个 parser 用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，218 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，218 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - Duplicate Basename Report Provenance Hardening

### 本轮目标
- 继续优化 `1.4.4` 发布候选，不进入发布流程。
- 修复真实样本复盘中暴露的同名日志展示问题：不同目录下同名文件在 summary、JSON、HTML、manifest、SARIF 中只显示 basename，容易让取证交付误以为是同一个输入文件。
- 保持 parser/detector 语义不变：解析器仍按原有 basename 识别日志类型，解析完成后仅在确有同名冲突时给展示用 `file_name/source_file` 加唯一相对后缀。

### 涉及模块
- `bla/core/pipeline.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 不改变 CLI 参数、parser registry、detector registry 和 remote 能力。
- 不把绝对路径写入报告；只使用最短唯一相对后缀，例如 `host-a/access.log`。
- 单文件或 basename 唯一的输入保持原有展示名称，降低兼容性风险。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_parse_files_disambiguates_duplicate_basenames_with_relative_labels`
- `python3 -m pytest -q tests/test_parsers.py tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 修改结果
- `parse_files` 预先计算输入文件展示名：basename 唯一时保持旧行为；basename 冲突时使用最短唯一相对后缀。
- 解析器仍按原始文件路径和 basename 选择/解析日志，解析完成后只改 `ParseResult.file_name` 和对应 `LogEvent.source_file` 的展示标签。
- 新增回归测试覆盖两个不同目录下的 `access.log`，确认输出为 `host-a/access.log` 与 `host-b/access.log`，且不泄露临时目录绝对路径。

### 剩余问题
- 定点回归通过。
- `tests/test_parsers.py tests/test_outputs.py` 通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，217 个用例通过。
- `python3 -m unittest discover -s tests -v` 通过，217 个用例通过。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、remote help、benchmark、memory benchmark、样例 smoke、P0 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未改版本号，未发布。

## 2026-05-30 - Release Build Candidate Check

### 本轮目标
- 在用户确认“好”后，继续做发布前置检查：审当前未提交范围、确认版本面，并运行 build 级发布检查。
- 验证 wheel / sdist 构建、twine 元数据检查和关键新增 parser 是否进入发行包。
- 仍不发布、不打 tag、不推送，发布前先向用户汇报。

### 涉及模块
- `scripts/release_check.py`
- `setup.py`
- `pyproject.toml`
- `bla/__version__.py`
- `dist/` 本地构建产物
- 间接覆盖 parser / detector / output / remote / benchmark / smoke

### 风险边界
- 本轮只运行本地 build 与包内容检查；未上传 PyPI，未创建 GitHub Release，未创建 git tag。
- `dist/` 产物为本地构建输出且未进入 git status；不把构建产物加入源码提交范围。
- 不修改 remote 能力，不改变默认离线运行原则。

### 验证命令
- `git status --short`
- `git diff --stat`
- `python3 scripts/release_check.py --build`
- `unzip -l dist/blueteam_log_analyzer-1.4.3-py3-none-any.whl bla/parsers/windows_json.py`
- `tar -tzf dist/blueteam_log_analyzer-1.4.3.tar.gz | rg 'bla/parsers/windows_json.py|docs/real-data-validation-report.md'`
- `git ls-files --others --exclude-standard dist build '*.egg-info'`
- `git tag --list 'v*' --sort=-v:refname | head -20`
- `git ls-remote --tags --refs origin 'refs/tags/v1.4.3'`
- `git diff --check`

### 验证结果
- 当前源码工作树仍为未提交累计改动：parser、detector、output、安全清洗、测试和文档；新增 `bla/parsers/windows_json.py` 与 `docs/real-data-validation-report.md`。
- `python3 scripts/release_check.py --build` 通过，包含 compileall、pytest、unittest、strict rules、ssh/remote-log help、benchmark、smoke、`python3 -m build` 和 `twine check`。
- 本地构建产物生成：
  - `dist/blueteam_log_analyzer-1.4.3-py3-none-any.whl`，470,159 bytes。
  - `dist/blueteam_log_analyzer-1.4.3.tar.gz`，12,029,519 bytes。
- wheel 明确包含 `bla/parsers/windows_json.py`。
- sdist 明确包含 `bla/parsers/windows_json.py` 与 `docs/real-data-validation-report.md`。
- `git ls-files --others --exclude-standard dist build '*.egg-info'` 无输出，构建产物未污染待提交源码范围。
- 本地与远端均已有 `v1.4.3` tag；本轮新能力不能继续沿用 `1.4.3` 作为正式发布版本号。
- `git diff --check` 通过。

### 修改结果
- 本轮未改业务代码，仅补充发布 build 候选检查记录。
- 当前没有发布任何新版本，没有 tag，没有 push，没有上传。

### 剩余问题
- 正式发布前还需做最终人工 diff review，并补新版本 release notes。
- 建议正式发布版本号使用 `1.4.4`，因为 `v1.4.3` 已存在于本地和远端；若决定进入发布流程，应先更新 `bla/__version__.py`、README 当前版本区和 `docs/releases/v1.4.4.md`，随后重跑完整 release gate 与 build gate。

## 2026-05-30 - Release Gate Recheck After Windows JSON Parser

### 本轮目标
- 回答“是否可以发布新版本”，在不打 tag、不构建、不上传的前提下，用默认 `python3` 复跑发布级门禁。
- 确认上一轮 Windows JSON EventLog parser、Splunk/OTRF 真实样本修复、输出安全和 remote 只读边界没有引入回归。
- 将发布判断写入计划文档，发布前继续向用户汇报，不擅自发布。

### 涉及模块
- `BLA_OPTIMIZATION_PLAN.md`
- 发布验证入口：`scripts/release_check.py`
- 间接覆盖 parser / detector / correlation / output / remote / benchmark smoke

### 风险边界
- 本轮只做验证和文档记录，不修改检测规则、不修改 parser、不修改 remote 能力。
- 不运行 `scripts/release_check.py --build`，不生成正式发布包，不打 tag，不推送，不上传 PyPI/GitHub Release。
- 验证均为本地离线执行；`release_check.py` 仅使用仓库内样例、fixture、benchmark 和 CLI help。

### 验证命令
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `python3 bla_cli.py benchmark --size-mb 1`
- `python3 bla_cli.py benchmark --size-mb 1 --memory`
- `git diff --check`

### 验证结果
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过，216 个 pytest 用例全绿。
- `python3 -m unittest discover -s tests -v` 通过，216 个 unittest 用例全绿。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `python3 scripts/release_check.py` 通过，覆盖 compileall、pytest、unittest、strict rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `python3 bla_cli.py benchmark --size-mb 1` 通过：1.00 MB、6,833 事件、44 告警、4 incident、0.545s、1.84 MB/s。
- `python3 bla_cli.py benchmark --size-mb 1 --memory` 通过：1.00 MB、6,833 事件、44 告警、4 incident、1.817s、0.55 MB/s、peak memory 32.95 MB。
- `git diff --check` 通过。

### 修改结果
- 本轮未改业务代码，仅补充发布门禁复核记录。
- 当前累计改动仍处于未提交工作树状态，没有发布任何新版本。

### 剩余问题
- 技术门禁已满足发布候选要求，但正式发布前仍需做人工发布汇报、版本号/CHANGELOG 核对、`scripts/release_check.py --build`、commit/tag/GitHub Release/PyPI 等发布动作。
- 工作树包含多轮累计修改和新文件，发布前应先做一次 diff review，确认每个变更都属于本次版本范围。
- `files_analyzed` 同名 basename 展示压缩问题仍是已知非阻塞改进项；manifest 仍保留输入、输出和 hash。

## 2026-05-30 - OTRF Windows JSON EventLog Parser Review

### 本轮目标
- 延续上一轮 Splunk Attack Data / OTRF Security-Datasets 验证，针对 OTRF Windows JSON 样本当前被 P0/generic JSON 路径解析导致的噪声做最小架构内修复。
- 新增独立 Windows JSON EventLog parser，通过 ParserRegistry 注册，支持 OTRF/Mordor 风格 JSONL、JSON sequence 与 JSON array，避免继续扩大 P0 parser 职责。
- 复用 Windows EVTX/XML 既有事件分类逻辑，保证 auditpol、防御规避、UAC registry、Sysmon 等检测语义一致，避免按样本路径、固定用户、固定域名过拟合。

### 涉及模块
- `bla/parsers/__init__.py`
- `bla/parsers/windows_evtx.py`
- `bla/parsers/windows_json.py`
- `tests/test_parsers.py`
- `docs/real-data-validation-report.md`
- `BLA_OPTIMIZATION_PLAN.md`
- 外部临时样本目录 `/tmp/bla-splunk-otrf-review-20260530/otrf`

### 风险边界
- 不保存第三方 OTRF 原始日志到仓库，只用 `/tmp` 中已下载公开样本做本地验证。
- Parser 只负责 JSON Windows EventLog 字段归一为 `LogEvent`；detector 仍只从事件生成告警，不把样本文件名或目录名写进规则。
- 文件解析优先逐行/流式处理 JSONL 与 JSON sequence；JSON array 使用增量 decoder，避免大日志整文件读入。
- 不修改 remote 模块，不增加默认联网行为，不进入发布构建或发布流程。

### 验证命令
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py /tmp/bla-splunk-otrf-review-20260530/otrf --profile cn-hvv --no-color --max-alerts 20 --exit-on none --out /tmp/bla-splunk-otrf-review-20260530/otrf-json-after2`
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py /tmp/bla-splunk-otrf-review-20260530/splunk /tmp/bla-splunk-otrf-review-20260530/otrf --profile cn-hvv --no-color --max-alerts 40 --exit-on none --out /tmp/bla-splunk-otrf-review-20260530/windows-json-after`
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest tests.test_parsers.ParserRegressionTests.test_windows_json_eventlog_auto_parse_uses_windows_parser tests.test_parsers.ParserRegressionTests.test_windows_json_array_parse_reuses_uac_registry_classification tests.test_detection.DetectionRegressionTests.test_windows_eventlog_multisource_incident_title_is_not_p0 -v`
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest tests.test_parsers tests.test_detection -v`
- `PYTHONPATH=. /usr/bin/python3 -m compileall -q bla bla_cli.py setup.py tests`
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest discover -s tests -v`
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py validate-rules --strict-metadata`
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1`
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1 --memory`
- `git diff --check`

### 验证结果
- OTRF Windows JSON 子集复跑到 `/tmp/bla-splunk-otrf-review-20260530/otrf-json-after2`：4 个 JSON 文件均识别为 `Windows Event Log (JSON)`，共 22,080 事件、7 告警、1 incident、IOC 181 项。
- OTRF JSON 事件不再走 P0/generic 安全设备路径；`auditpol_system_user_auditpolicy_modification.json` 命中 `EVAS-002 / T1562.002`，`empire_uac_shellapi_fodhelper_2020-09-04032946.json` 命中 `PRIV-006 / T1548.002`，`cmd_bitsadmin_download_psh_script_2020-10-2302365189.json` 命中 `EXEC-002 / T1218`。
- OTRF JSON 子集 parse time：424 事件 60ms、3,872 事件 271ms、13,645 事件 349ms、4,139 事件 438ms；文件解析未整文件读入 JSONL。
- Splunk + OTRF 合集复跑到 `/tmp/bla-splunk-otrf-review-20260530/windows-json-after`：32,750 事件、9 告警、1 incident、风险 `100/critical`，输出 HTML/JSON/CSV/IOC/SARIF/manifest，IOC 629 项。
- 合集报告中的 OTRF JSON 文件 log type 均为 `Windows Event Log (JSON)`；Splunk XML 仍为 `Windows Event Log (XML)`。
- Windows EventLog 多源 incident 标题从误导性的 `P0 多源关联案件` 修正为 `多源关联案件`；P0 安全设备多源标题仍保留 P0 前缀。
- 定点回归通过：Windows JSONL 自动选择 windows-json parser、Windows JSON array 复用 UAC registry 分类、Windows EventLog 多源 incident 不再标成 P0。
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest tests.test_parsers tests.test_detection -v` 通过，101 个相关回归用例通过。
- `PYTHONPATH=. /usr/bin/python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `PYTHONPATH=tests:. /usr/bin/python3 -m unittest discover -s tests -v` 通过，216 个测试通过。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1` 通过：1.00 MB、6,833 事件、0.735s、1.36 MB/s。
- `PYTHONPATH=. /usr/bin/python3 bla_cli.py benchmark --size-mb 1 --memory` 通过：1.00 MB、6,833 事件、1.517s、0.66 MB/s、peak memory 35.74 MB。
- `git diff --check` 通过。
- 本轮默认 `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3` 在本机桌面环境出现 `python3 -c 'print("hi")'` 卡住，未使用该解释器复跑 `python3 -m pytest -q` 和 `python3 scripts/release_check.py`；改用可执行的 `/usr/bin/python3` 完成 unittest/CLI/benchmark 验证。发布前仍需在正常 Python 3.12 环境补跑 pytest 与 release_check。

### 修改结果
- 新增 `bla/parsers/windows_json.py`，支持 Windows EventLog JSONL、JSON sequence 与 JSON array，按 ParserRegistry 注册为 `windows-json`，位置在 `p0-security` 之前。
- `windows_json` parser 只做 Windows EventLog 字段识别、流式 JSONL/array 解码和字段字符串化，不引入检测逻辑、不扩大 P0 parser。
- `windows_evtx` 抽出 `build_windows_event_from_fields`，XML/EVTX/JSON 共用同一套 Windows 事件增强与分类逻辑，避免 auditpol、UAC registry、Sysmon 语义分叉。
- `correlation` 多源 incident 标题改为按 source_type 判断：纯 P0 安全设备/EDR 多源保留 `P0 多源关联案件`，Windows EventLog 混合源使用通用 `多源关联案件`。
- 新增 parser 与 incident 标题回归测试。
- 更新真实数据报告记录 OTRF JSON 专用 parser 结果。

### 剩余问题
- 默认 Python 3.12 解释器在本轮验证中卡住，导致未能用原始 `python3` 命令复跑 pytest/release_check；发布前必须在正常解释器环境补跑完整发布门禁。
- OTRF JSON 仍会保留大量 Sysmon 10 中危进程访问事件；当前不进入凭据告警，后续可以研究 LSASS 合法访问基线以降低事件噪声。
- `files_analyzed` summary 仍按 basename 压缩同名 `windows-sysmon.log`，manifest 和 `files` 列表保留输入输出信息；后续应改为相对路径展示。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

## 2026-05-30 - Splunk/OTRF Windows C2 Exfil Defense UAC Review

### 本轮目标
- 按用户要求继续过 Splunk Attack Data / OTRF Security-Datasets，重点复查 Windows C2、数据外传、防御规避和 UAC 提权样本。
- 修复真实 Splunk Windows XML 样本被解析为 0 事件的通用兼容性问题。
- 从真实样本中抽象通用行为检测：DNS/base64 外传、`auditpol` 审计策略清除/禁用、防御规避命令；避免按样本文件名、固定域名、固定 IP 或固定用户过拟合。
- 记录 OTRF Windows JSON 样本当前被 P0/generic JSON 路径解析产生的噪声，作为后续 Windows JSON parser 专项。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`
- `docs/real-data-validation-report.md`
- `BLA_OPTIMIZATION_PLAN.md`
- 外部临时样本目录 `/tmp/bla-splunk-otrf-review-20260530`

### 风险边界
- 只下载公开 Splunk Attack Data / OTRF Security-Datasets 样本到 `/tmp`；不保存第三方原始日志到仓库。
- 联网仅用于本轮人工取样验证，不进入 BLA 默认运行路径；BLA 仍保持离线、无上传、HTML 无 CDN。
- 不基于样本路径、文件名、固定 IP、固定域名或固定用户名写规则；只抽象 Windows XML 结构、Sysmon 进程/DNS/注册表语义和 ATT&CK 行为。
- 不修改 remote 模块，不扩展远程任意命令执行能力。
- OTRF JSON 噪声先记录为剩余风险；本轮不做大规模 parser 重写。

### 验证命令
- `python3 bla_cli.py /tmp/bla-splunk-otrf-review-20260530/splunk /tmp/bla-splunk-otrf-review-20260530/otrf --profile cn-hvv --no-color --max-alerts 40 --exit-on none --out /tmp/bla-splunk-otrf-review-20260530/baseline`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_xml_single_quoted_default_namespace_is_parsed`
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_benign_sysmon_network_dns_do_not_create_c2_alert tests/test_detection.py::DetectionRegressionTests::test_sysmon_dns_long_encoded_query_creates_exfil_alert tests/test_detection.py::DetectionRegressionTests::test_auditpol_tampering_command_creates_defense_evasion_alert tests/test_detection.py::DetectionRegressionTests::test_uac_bypass_registry_change_creates_privilege_alert`
- `python3 bla_cli.py /tmp/bla-splunk-otrf-review-20260530/splunk /tmp/bla-splunk-otrf-review-20260530/otrf --profile cn-hvv --no-color --max-alerts 40 --exit-on none --out /tmp/bla-splunk-otrf-review-20260530/after3`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- Splunk Attack Data 6 个 Windows XML/LFS 小样本和 OTRF Security-Datasets 4 个 Windows JSON zip 下载到 `/tmp/bla-splunk-otrf-review-20260530`，样本哈希记录在 `docs/real-data-validation-report.md`。
- 基线报告生成到 `/tmp/bla-splunk-otrf-review-20260530/baseline`：20,980 事件、7 告警、1 incident，风险 `100/critical`。其中 5 个 Splunk Windows XML 样本因单引号默认 XML namespace 解析为 0 事件。
- 修复后最终报告生成到 `/tmp/bla-splunk-otrf-review-20260530/after3`：31,650 事件、11 告警、3 incidents，风险 `100/critical`，输出 HTML/JSON/CSV/IOC/SARIF/manifest，IOC 6,240 项。
- `dns-sysmon.log` 从 0 事件恢复为 10 事件；`windows-sysmon_curl_upload.log` 从 0 恢复为 338 事件；`auditpol_tampering_sysmon.log` 从 0 恢复为 17 事件；两个 `windows-sysmon.log` 分别恢复为 2,950 / 7,340 事件。
- `auditpol_tampering_sysmon.log` 生成 `EVAS-002 / T1562.002`，8 条 auditpol 清除、移除、禁用或 SDDL 篡改命令进入防御规避 incident。
- `T1048.003/nslookup_exfil` 与 `T1071.004/long_dns_query` 生成 `EXFIL-002 / T1048.003`，168 条 DNS 编码查询或查询命令进入数据外传；同一 DNS tunnel 行为以 `C2-001 / T1071.004` 低噪声给出命令控制视角。
- `T1548.002/ssa_eventvwr` 生成 `PRIV-006 / T1548.002`，2 条 `HKU\\SID_Classes\\mscfile\\shell\\open\\command` 注册表修改进入权限提升 incident。
- 初版增强中发现 AD `_ldap._tcp..._msdcs` SRV 查询会被 `ldap` 关键词误判为 callback；已收紧 callback 规则，正常 AD LDAP SRV 查询不再触发 C2。
- 定点 parser 回归通过：Windows XML 单引号默认 namespace 可解析。
- 定点 detection 回归通过：正常 Sysmon 网络/DNS 不触发 C2、长编码 DNS 触发外传、auditpol tampering 触发防御规避、UAC registry 触发权限提升。
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py` 通过，98 个相关回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，213 个测试通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `python3 scripts/release_check.py` 通过，包含 compileall、pytest、unittest、validate-rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0 fixture 和 v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。

### 修改结果
- `windows_evtx` parser 的 XML namespace 清洗支持单双引号和命名 namespace 属性，修复真实 Splunk XML 导出样本被静默解析为 0 事件的问题，仍保持流式 XML block 解析。
- `windows_evtx` parser 新增 DNS 编码外传启发式：仅在 DNS 工具命令或可疑进程发起长编码子域时标记 `dns-exfiltration` / `dns-tunnel` / `data-exfiltration`，避免按固定域名或文件名判断。
- `windows_evtx` parser 新增 auditpol tampering 识别：`/clear`、`/remove`、`/success:disable`、`/failure:disable`、`/value:disable`、`/logon:none`、`/sd:` 升级为 `audit-policy` / `defense-evasion` / `T1562.002`。
- `windows_evtx` parser 新增 UAC bypass registry 识别：覆盖 `HKCU\\Software\\Classes`、`HKU\\SID_Classes` 和 `LocalAccountTokenFilterPolicy` 等常见注册表路径，标记 `uac-bypass` / `T1548.002`。
- `detection` 新增 `EXFIL-002 DNS 数据外传/隧道` 和 `PRIV-006 UAC 绕过痕迹`；Sysmon C2 聚合对 DNS tunnel 使用 `T1071.004`，避免命令控制告警继承外传技术号。
- `enrichment` 将 `data-exfiltration` / `dns-exfiltration` 优先归为数据外传阶段，避免被 `dns-tunnel` 抢先归入命令控制。
- 收紧 Sysmon callback domain 识别，不再将普通 `ldap` 字符串当 callback 域名，避免域控 SRV 发现流量误报。
- 新增真实样本驱动回归测试，并更新 `docs/real-data-validation-report.md` 与 `docs/testing-resources.md`。

### 剩余问题
- OTRF Windows JSON 样本当前仍走 P0/generic JSON 适配器，能提供 EDR/WAF 风险视图，但会把大量 Windows EventLog `Message` 泛化为 Web/EDR 告警；后续应新增独立 Windows JSON EventLog parser，而不是继续扩大 P0 parser。
- `files_analyzed` 仍按 `source_file` basename 去重，两个不同目录同名 `windows-sysmon.log` 在 summary 中计为一个同名文件；manifest 保留输入 hash，但 summary 计数后续应使用相对路径。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

## 2026-05-30 - Real EVTX Windows Attack Samples Review

### 本轮目标
- 按用户要求继续使用公开真实 Windows/EVTX 攻击样本逐条复查，避免按样本文件名、固定 IP、固定路径过拟合。
- 修复真实样本暴露的通用问题：Sysmon 10 非 LSASS 进程访问被误标为凭据转储、PowerShell 4104 LSASS MiniDump 脚本块漏识别、Sysmon WMI 19/20/21 持久化语义缺失、WMI 远程执行链路缺少 detector 告警。
- 生成本地完整报告，并记录仍需人工基线判断的样本。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`
- `docs/real-data-validation-report.md`
- `BLA_OPTIMIZATION_PLAN.md`
- 外部临时样本目录 `/tmp/bla-evtx-real-data-api-db8068`
- 外部报告目录 `/tmp/bla-evtx-real-review-api-db8068`

### 风险边界
- 只下载公开 EVTX-ATTACK-SAMPLES 小样本到 `/tmp`；不保存第三方原始 EVTX 到仓库。
- 联网只用于本轮人工取样验证，不进入 BLA 默认运行路径；BLA 运行仍保持离线、无上传、HTML 无 CDN。
- 不基于样本文件名、固定用户名、固定路径、固定 IP 写规则；只抽象为通用 Windows 事件语义和跨事件时间窗检测。
- 不修改 remote 模块，不扩展任意命令执行能力。

### 验证命令
- `python3 bla_cli.py /tmp/bla-evtx-real-data-api-db8068 --profile cn-hvv --no-color --max-alerts 20 --exit-on none --out /tmp/bla-evtx-real-review-api-db8068/baseline`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_sysmon_process_access_non_lsass_is_not_credential_dump tests/test_parsers.py::ParserRegressionTests::test_powershell_4104_minidump_lsass_is_credential_dump tests/test_parsers.py::ParserRegressionTests::test_sysmon_wmi_subscription_events_are_persistence`
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_non_lsass_sysmon_access_does_not_create_credential_alert tests/test_detection.py::DetectionRegressionTests::test_windows_wmi_remote_execution_chain_creates_lateral_alert tests/test_detection.py::DetectionRegressionTests::test_wmi_persistence_events_create_persistence_alert`
- `python3 bla_cli.py /tmp/bla-evtx-real-data-api-db8068 --profile cn-hvv --no-color --max-alerts 20 --exit-on none --out /tmp/bla-evtx-real-review-api-db8068/after`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- EVTX-ATTACK-SAMPLES 7 个小样本下载到 `/tmp/bla-evtx-real-data-api-db8068`，样本哈希记录在 `docs/real-data-validation-report.md`。
- 基线报告生成到 `/tmp/bla-evtx-real-review-api-db8068/baseline`：49 事件、6 告警、4 incidents，风险 `100/critical`。
- 修复后报告生成到 `/tmp/bla-evtx-real-review-api-db8068/after`：49 事件、9 告警、5 incidents，风险 `100/critical`，输出 HTML/JSON/CSV/IOC/SARIF/manifest。
- UACME 样本中 5 条非 LSASS Sysmon 10 进程访问不再带 `T1003.001`、`lsass` 或 `credential-access`。
- PowerShell 4104 `MiniDumpWriteDump` + `lsass` 脚本块升级为严重 `T1003.001`，进入 `CRED-001` / `CRED-002`。
- Sysmon WMI 19/20/21 创建动作识别为 `T1546.003` / `wmi-persistence`，WMIC `DELETE` 不再计入持久化创建。
- `LM_WMI_4624_4688_TargetHost.evtx` 生成 `LAT-003 WMI 远程执行链`，关联 5 条事件，ATT&CK 攻击链出现 `横向移动 / T1047`。
- 定点 parser 回归通过：非 LSASS Sysmon 10、4104 LSASS MiniDump、WMI 订阅创建、WMI 订阅删除。
- 定点 detection 回归通过：非 LSASS 不触发凭据告警、WMI 远程执行链、WMI 持久化告警、P0 golden attack chain 稳定性。
- `python3 -m pytest -q tests/test_parsers.py` 通过，46 个 parser 回归用例通过。
- `python3 -m pytest -q tests/test_detection.py` 通过，47 个 detection 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `python3 -m pytest -q` 通过，209 个测试通过。
- `python3 -m unittest discover -s tests -v` 通过，209 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 compileall、pytest、unittest、validate-rules、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark、样例 smoke、P0 fixture 和 v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。

### 修改结果
- `windows_evtx` parser 将 Sysmon 10 默认语义调整为普通 `process-access`，只有 `TargetImage` 指向 LSASS 时才标记 `lsass-dump` / `credential-access` / `T1003.001`。
- `windows_evtx` parser 新增 PowerShell 4104 LSASS MiniDump 脚本块识别，要求脚本同时包含 `lsass` 与 `MiniDumpWriteDump`，避免按样本文件名或固定路径判断。
- `windows_evtx` parser 新增 Sysmon 19/20/21 WMI Event Filter / Consumer / Binding 语义，按 `Operation=Created` 标记 WMI 持久化，`Deleted` 保留为订阅变更证据但不进持久化创建告警。
- `windows_evtx` parser 识别 WMIC `root\subscription` 创建命令为 `wmi-persistence`，只对 `CREATE` 动作升级，避免把清理命令当成持久化创建。
- `detection` 在既有 lateral detector 内新增 WMI 远程执行链判断：网络登录后 2 分钟内目标主机出现 WMI 进程，生成 `LAT-003 / T1047`，并通过 selector 预筛 `remote-access` / `wmi` 事件。
- `detection` 在既有 persistence detector 内新增 `PERS-005 / T1546.003`，聚合 WMI 事件订阅持久化。
- attack chain 增加 `T1047` 与 `T1546` 阶段映射，并仅允许横向移动这类跨事件告警补充链路阶段，避免破坏 P0 golden 事件计数。
- 新增真实样本驱动回归测试，并将本轮结果写入 `docs/real-data-validation-report.md` 与 `docs/testing-resources.md`。

### 剩余问题
- `UACME_59_Sysmon.evtx` 不再误标凭据访问，但仍未专门定性为 UAC bypass；仅凭该小样本的 Sysmon 10/1 证据不足，后续应使用更完整的 UAC registry/file/process 样本抽象通用提权规则。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。
- 下一批建议继续按同样方式过 Splunk Attack Data / OTRF Security-Datasets 中的 Windows C2、数据外传和防御规避样本。

## 2026-05-29 - Real Data Stepwise Review: SecRepo Auth/Web

### 本轮目标
- 按用户要求“一条一条过真实数据”，在本地终端复跑公开真实样本，生成完整交付包。
- 对每条样本检查误报、漏识别和噪声事件，并把发现转成最小修复与回归测试。
- 输出完整本地报告，明确哪些命中保留、哪些噪声过滤、哪些数据源留到下一批。

### 涉及模块
- `bla/parsers/linux_auth.py`
- `bla/parsers/web_access.py`
- `tests/test_parsers.py`
- `docs/real-data-validation-report.md`
- `docs/secrepo-sample-validation.md`
- `BLA_OPTIMIZATION_PLAN.md`
- 外部临时目录 `/tmp/bla-hvv-real-data-rAgDex`
- 外部报告目录 `/tmp/bla-real-review-rAgDex`

### 风险边界
- 只处理公开 SecRepo 样本；不下载客户/生产/真实重保现场日志。
- 联网下载不进入 BLA 默认运行路径；本轮分析只读本地临时样本并输出本地报告。
- 不上传日志，不保存原始第三方样本到仓库，不修改 remote 模块。
- Parser 调整只过滤真实数据中确认的重复/正常噪声，不降低已有明确攻击命中：SSH 暴力破解、认证失败过多、Web 敏感路径、扫描器、`cmd=id` 命令执行样例均保留。

### 验证命令
- `python3 bla_cli.py /tmp/bla-hvv-real-data-rAgDex/auth.log --syslog-year 2015 --no-color --max-alerts 10 --exit-on none --out /tmp/bla-real-review-rAgDex/auth/report`
- `python3 bla_cli.py /tmp/bla-hvv-real-data-rAgDex/access.log --profile cn-hvv --no-color --max-alerts 10 --exit-on none --out /tmp/bla-real-review-rAgDex/access/report`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_linux_auth_filters_duplicate_preauth_invalid_user_and_keeps_lockout`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_web_parser_filters_benign_redirects_without_losing_sensitive_redirect tests/test_parsers.py::ParserRegressionTests::test_web_parser_does_not_flag_browser_ua_or_id_param_as_command tests/test_parsers.py::ParserRegressionTests::test_web_parser_still_detects_command_execution_params`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- SecRepo auth 完整报告生成到 `/tmp/bla-real-review-rAgDex/auth/report`，包含 HTML/JSON/CSV/IOC/SARIF/manifest。
- SecRepo Web 完整报告生成到 `/tmp/bla-real-review-rAgDex/access/report`，包含 HTML/JSON/CSV/IOC/SARIF/manifest。
- auth 修复前：27,075 事件、447 告警、30 incidents，其中 14,825 条事件显示 `来源=?`。
- auth 修复后：14,825 事件、447 告警、30 incidents，风险 `100/critical`；12,250 条有来源 IP 的 `Invalid user ... from IP` 全部保留，12,250 条无来源 `input_userauth_request: invalid user ... [preauth]` 重复行过滤，2,575 条 `Too many authentication failures` 识别为 `认证失败次数过多` 高危 lockout 事件，`failed-login` 无来源事件为 0。
- Web 修复前：246 事件、5 告警、2 incidents，其中 104 条普通 301/304 作为 `INFO Web` 事件进入报告。
- Web 修复后：142 事件、5 告警、2 incidents，风险 `100/critical`；118 条 `wp-login.php`、12 条 `wp-admin`、7 条 `python-requests`、2 条 `Wget` 均保留；56 条普通根路径/静态资源 3xx 过滤，INFO 事件为 0。
- Linux auth 定点回归通过。
- Web redirect/UA/命令执行定点回归通过。
- `python3 -m pytest -q tests/test_parsers.py` 通过，43 个 parser 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，202 个测试通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。

### 修改结果
- Linux auth parser 过滤无来源的 `input_userauth_request: invalid user` preauth 重复行，避免真实 OpenSSH 日志把同一失败尝试记成两条事件。
- Linux auth parser 将 `Too many authentication failures` 优先识别为 `认证失败次数过多` / `lockout`，避免被泛化为普通失败登录。
- Web access parser 过滤无攻击特征的 2xx/3xx 正常响应，降低普通跳转、缓存响应对事件视图和 Top IP 的污染；敏感路径/扫描器命中不受影响。
- 新增真实样本驱动回归测试，并生成 `docs/real-data-validation-report.md`。

### 剩余问题
- 本批只完成 SecRepo auth/web 两条公开真实数据；下一批应继续按同样方式过 EVTX-ATTACK-SAMPLES 小样本、Splunk Attack Data 小目录、Mordor/Security-Datasets 可直接转换样本。
- SecRepo Web 中 `106.51.67.207` 高频访问仍保留为中危 volume alert，需要后续结合真实业务基线或 allowlist 决定是否压制。
- 未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

## 2026-05-29 - Public HVV Data Smoke and Web FP Tuning

### 本轮目标
- 查找公开、可合法复现、接近 HVV/重保场景的真实或准真实蓝队日志数据源。
- 优先用小体量真实日志跑 BLA smoke，验证真实 Linux auth.log 和 Web access.log 兼容性。
- 用真实 Web access.log 反查误报，修复浏览器 User-Agent 分号和普通 `id=123` 业务参数被误判为命令注入的问题。
- 不下载客户/生产/真实重保现场日志，不把大体量公开数据集直接放进仓库。

### 涉及模块
- `bla/parsers/web_access.py`
- `tests/test_parsers.py`
- `docs/secrepo-sample-validation.md`
- `docs/testing-resources.md`
- `BLA_OPTIMIZATION_PLAN.md`
- 外部临时目录 `/tmp/bla-hvv-real-data-*`

### 风险边界
- 本轮只修改 Web access parser 的通用命令执行启发式，避免把常规浏览器 User-Agent 或业务 ID 参数误判为命令注入。
- 保留 SQLi、XSS、路径穿越、Webshell、扫描器、`cmd=id` 等明确攻击特征检测；不改 detector/correlation/output/remote 代码。
- 不引入默认联网行为；联网下载只作为本轮人工验证动作，不进入 BLA 默认运行路径。
- 不上传任何日志，不保存真实公开样本到仓库，不修改远端状态。

### 验证命令
- `python3 - <<'PY' ... import evtx ... PY`
- `curl -L --fail --max-time 60 -o /tmp/.../auth.log.gz https://www.secrepo.com/auth.log/auth.log.gz`
- `curl -L --fail --max-time 60 -o /tmp/.../access.log.gz https://www.secrepo.com/self.logs/access.log.2017-05-15.gz`
- `gunzip -c /tmp/.../auth.log.gz > /tmp/.../auth.log`
- `gunzip -c /tmp/.../access.log.gz > /tmp/.../access.log`
- `wc -l -c /tmp/.../auth.log /tmp/.../access.log`
- `shasum -a 256 /tmp/.../auth.log.gz /tmp/.../access.log.gz`
- `python3 bla_cli.py /tmp/.../auth.log --no-color --max-alerts 5 --exit-on none --json /tmp/.../auth-report.json`
- `python3 bla_cli.py /tmp/.../access.log --no-color --max-alerts 5 --exit-on none --json /tmp/.../access-report.json`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_web_parser_does_not_flag_browser_ua_or_id_param_as_command tests/test_parsers.py::ParserRegressionTests::test_web_parser_still_detects_command_execution_params`
- `python3 bla_cli.py /tmp/.../access.log --profile cn-hvv --no-color --max-alerts 5 --exit-on none --json /tmp/.../access-report-after-fp-fix.json`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- `python-evtx` 当前环境可用。
- SecRepo `auth.log.gz`、`access.log.2017-05-15.gz` 下载到 `/tmp/bla-hvv-real-data-rAgDex` 并通过 `gzip -t`。
- 样本规模：`auth.log` 86,839 行 / 9,334,022 bytes；`access.log` 2,928 行 / 660,951 bytes。
- 样本 SHA256：`auth.log.gz` 为 `b963369529d0ccda482d373d08fef44eda0f212dd6d8f93906d11f02f830e429`；`access.log.gz` 为 `1e2fb015999883ebf36b3059e78e85d282f6d60eb7e3d21066f0ffe8d51587dd`。
- `auth.log` smoke 通过：解析 27,075 个 Linux Auth 事件，生成 447 个告警、30 个 incident，风险 `100/critical`，主要为 SSH 暴力破解 `BRUTE-001`。
- `access.log` 修复前 smoke 复现误报：解析 1,427 个事件，`Web攻击` 1,264 个，其中大量普通 `GET /`、静态资源访问因浏览器 User-Agent 分号被标记为 `可疑参数/命令特征`。
- Web 误报定点回归通过，确认普通浏览器 UA 和 `/article?id=123` 不再生成攻击事件，`/vuln.php?cmd=id` 仍识别为 `命令注入/代码执行`。
- `access.log` 修复后 smoke 通过：解析 246 个事件，生成 5 个告警、2 个 incident，风险 `100/critical`；保留敏感文件探测、安全扫描器、自动化扫描告警，移除 1,257 条泛化 `可疑参数/命令特征` 误报。
- `python3 -m pytest -q tests/test_parsers.py` 通过，41 个 parser 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，200 个测试通过。
- `python3 bla_cli.py validate-rules --strict-metadata` 通过，3 条规则、4 个编译模式，0 error / 0 warning。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已确认真实 HVV/重保现场日志通常不能公开流通；本轮候选限定为公开授权或公开可下载的数据集，用于模拟护网常见的 SSH 爆破、Web 扫描/漏洞探测、Windows/Sysmon、代理/IDS/C2、数据外传等场景。
- 已将 Web parser 中命令执行启发式改为要求命令参数、命令分隔符后跟命令词、或参数值明确为命令词，不再把 User-Agent 中的正常分号或普通 `id=123` 当成攻击。
- 已新增回归覆盖真实 SecRepo 风格浏览器 UA、普通业务 ID 参数和 `cmd=id` 命令执行参数。
- 已将本轮 SecRepo 增量复验结果写入 `docs/secrepo-sample-validation.md`，并将可持续使用的公开 HVV/重保近似数据源矩阵写入 `docs/testing-resources.md`。

### 剩余问题
- 未下载 EVTX-ATTACK-SAMPLES、OTRF Security-Datasets、Splunk BOTS v3 或 Splunk Attack Data 的大体量数据；这些适合作为下一阶段专项 smoke/转换脚本验证。
- 真实客户 HVV/重保日志仍不能公开流通，后续若接入必须先脱敏、授权、限定离线环境。

## 2026-05-29 - Summary Alert Evidence Sanitization

### 本轮目标
- 修复 `AnalysisSummary.alerts` 中 detector 原始 evidence 直接引用事件 `message`，导致 Web 聚合告警 `示例:` 证据在二次处理 summary 对象时仍可能带出 token、session 或终端控制字符的问题。
- 保留 `alert.id` 与 `affected_events` 的引用语义，只清洗告警的人类可读展示字段。
- 保持 parser 原始事件不被改写，detector 仍只从事件生成 `DetectionAlert`，output 仍负责最终 HTML/JSON/CSV/IOC/SARIF/manifest 落地。

### 涉及模块
- `bla/detection/engine.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只清洗返回给 summary 的告警展示字段：`rule_id`、`rule_name`、`description`、`category`、`mitre_attack`、`mitre_phase`、`evidence`、`recommendation`、`timestamp`、`confidence`。
- 不改写 `LogEvent.message` / `raw_line`，不修改 `DetectionAlert.id` 和 `affected_events`，避免破坏 alert/incident/event 引用。
- 不改变告警触发条件、严重级别、incident 关联、attack chain、输出格式或远程能力。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_summary_alerts_sanitize_evidence_without_mutating_events`
- `python3 -m pytest -q tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- Summary alert evidence sanitization 定点回归通过。
- `python3 -m pytest -q tests/test_detection.py` 通过，44 个 detection 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，198 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：包含 `access_token=super-secret` 和 OSC52 控制序列的 Web 攻击日志会生成 `WEB-SQL` 告警，`summary.alerts[0].evidence` 的原始 `示例:` 条目仍带出未清洗的事件消息。
- 已新增 `_sanitize_alert_display_fields()`，在 `run_detection()` 完成 attack chain、incident、risk 和建议生成后，统一清洗告警展示字段。
- 已保留 `DetectionAlert.id` 与 `affected_events` 不变，避免破坏 alert/incident/event 引用；原始 `LogEvent.message` / `raw_line` 仍保留取证内容。
- 新增回归确认 summary alert evidence 不再含 `super-secret` 或 ESC 控制符，同时原始事件未被改写。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - Summary Timeline Sanitization

### 本轮目标
- 修复 `AnalysisSummary.timeline` 直接引用事件 `message` / `source_file` 等人类可读字段，导致恶意 URL、User-Agent 或文件名中的 secret/终端控制字符在二次处理 summary 对象时被带出的风险。
- 保留原始 `LogEvent` 语义和事件 ID 关联，只清洗 summary 时间线这个面向报告/API/二次处理的视图。
- 保持 parser 只生成 `LogEvent`、detector 只生成告警、correlation 只关联 incident、output 只负责落地格式的架构边界。

### 涉及模块
- `bla/detection/engine.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只清洗 `_build_timeline()` 生成的 `TimelineEntry` 文本字段，不改写 `LogEvent.message`、`LogEvent.raw_line`、parser 字段、告警触发条件、attack chain、incident 关联或输出格式。
- 时间线排序仍使用原始事件时间和级别；事件 ID 正常值保持不变，恶意 ID 仅在展示视图中清洗。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_summary_timeline_sanitizes_event_messages_without_mutating_events`
- `python3 -m pytest -q tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- Summary timeline sanitization 定点回归通过。
- `python3 -m pytest -q tests/test_detection.py` 通过，43 个 detection 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，197 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：包含 `access_token=super-secret` 和 OSC52 控制序列的 Web 攻击日志进入 `summary.timeline[0].message` 时仍是未清洗文本，而 `LogEvent.message` / `raw_line` 本身也保留原始取证内容。
- 已将 `_build_timeline()` 生成的 `TimelineEntry` 文本字段统一送入 `sanitize_report_text`，覆盖 timestamp、category、message、event_id、source_file 和 MITRE 字段。
- 新增回归确认 summary timeline 不再含 `super-secret` 或 ESC 控制符，同时原始 `LogEvent.message` / `raw_line` 仍保留原始取证内容。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - Incident Evidence Sanitization

### 本轮目标
- 修复 correlation 生成 incident 时，`incident.evidence` 和 `incident.timeline` 直接引用事件 `message`，导致恶意 Web/User-Agent/URL 中的 `access_token`、`session_id` 或终端控制字符进入案件视图的问题。
- 保留 incident 对原始事件的关联 ID 和时间线语义，但案件视图中的人类可读文本必须先经过报告清洗。
- 保持 parser 原始事件不被改写，detector/correlation/output/remote 架构边界不变。

### 涉及模块
- `bla/detection/correlation.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只清洗 incident 视图文本，不修改 `LogEvent.message`、`LogEvent.raw_line`、parser 字段、告警触发条件、incident 关联键、排序、去重或输出格式。
- `affected_events` 仍引用原始事件 ID；incident timeline 仍保留原时间戳、级别、分类、事件 ID、来源文件和 MITRE。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_incident_evidence_and_timeline_sanitize_event_messages`
- `python3 -m pytest -q tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- Incident evidence/timeline sanitization 定点回归通过。
- `python3 -m pytest -q tests/test_detection.py` 通过，42 个 detection 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，196 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：包含 `access_token=super-secret` 和 OSC52 控制序列的 Web 攻击日志会生成 incident，`incident.evidence` 的关键事件摘要和 `incident.timeline.message` 均会带出未清洗的事件消息。
- 已在 correlation incident 视图层统一清洗 title、description、source/account/asset/source_type/phase 展示值、evidence、timeline message/source 字段、recommended_actions 和 next_logs。
- 原始 `LogEvent.message` / `raw_line`、`affected_events` 事件引用、incident 关联键、去重、排序、攻击阶段和输出格式均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Context Session Redaction

### 本轮目标
- 修复 P0 聚合告警上下文中 `session_id` 作为裸值展示时，清洗器无法根据字段名识别并脱敏会话令牌的问题。
- 保留 `会话=<redacted>` 这类取证提示，同时避免将真实 session/token 类值写入终端、JSON、HTML、SARIF 等报告证据。
- 保持 detector 只从事件生成 `DetectionAlert`，不改变 parser/correlation/output/remote 边界。

### 涉及模块
- `bla/detection/engine.py`
- `bla/detection/evidence.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只调整 P0 上下文 evidence 中 `session_id` 的脱敏方式，不改变事件 `details` 原始值、告警触发条件、事件级别、MITRE 映射、incident 关联、输出格式或远程采集能力。
- `trace_id` 仍按普通上下文字段展示，但会继续通过通用输出清洗器处理显式 secret 片段。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_alert_context_redacts_session_id_value`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 context session redaction 定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，51 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，195 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `compileall`、`pytest`、`unittest`、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、P0 fixture、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：包含 `session_id=sess-super-secret-token` 的 P0 代理事件会触发 `P0-C2-001`，告警 evidence 中出现 `会话=sess-super-secret-token`，而不是脱敏后的会话提示。
- 已将 P0 上下文中的敏感字段 `session_id` 按 `key=value` 形式送入统一报告清洗器，再只展示脱敏后的值，因此 evidence 保留 `会话=<redacted>`，不泄漏真实会话令牌。
- 已修复共享 alert evidence enrichment：scanner、request、referer、event id、raw log 等追加证据现在先经过 `sanitize_report_text`，避免原始日志证据重新带出 session/token 或终端控制字符。
- 本轮未改变 parser 输出、告警触发条件、MITRE 映射、incident 关联、输出格式或 remote 只读边界。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Terminal Evidence Priority

### 本轮目标
- 修复 P0 聚合告警 `P0上下文` 已进入 evidence，但默认终端报告只展示前三条证据时仍可能被隐藏的问题。
- 让设备、策略、网络区域、接口、租户等关键上下文在不使用 `--full` / `--no-truncate` 的默认终端输出中可见。
- 保持 output 层默认截断策略不变，只调整 P0 告警 evidence 的排序和紧凑性。

### 涉及模块
- `bla/detection/engine.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只调整 P0 聚合告警 evidence 的展示顺序和端点摘要，不改变告警触发条件、事件级别、MITRE 映射、incident 关联、输出格式或远程采集能力。
- 不改变终端报告的全局截断策略，不扩大默认输出体积。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_alert_evidence_includes_normalized_context`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 terminal evidence priority 定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，50 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，194 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：默认终端报告只展示 `alert.evidence[:3]`，而当前 P0 告警前三条是 `事件数`、`IP`、`主机/目标`，`P0上下文` 位于第 4 条，默认输出中不可见。
- 已将 P0 聚合告警的 IP 和主机/目标压缩为一条 `端点` 证据，并将 `P0上下文` 保持在前三条 evidence 中。
- 默认终端报告无需 `--full` / `--no-truncate` 即可看到 P0 设备、策略、区域、接口、租户等上下文；输出层全局截断策略、告警触发条件、严重级别、MITRE、incident 关联和远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Alert Evidence Context

### 本轮目标
- 修复 P0 聚合告警已经拥有 `device_name` / `policy_name` / `source_zone` / `destination_interface` 等稳定上下文，但 alert evidence 仍只展示事件数、IP、主机和示例的问题。
- 提升 HTML/JSON/终端/SARIF 等下游报告对 P0 设备、策略、签名、网络路径、租户/虚拟域的可读性。
- 保持 detector 只从事件生成 `DetectionAlert`，不改变 parser/correlation/output/remote 边界。

### 涉及模块
- `bla/detection/engine.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只补充 P0 聚合告警 `evidence` 的上下文摘要，不改变告警触发条件、事件级别、MITRE 映射、incident 关联、输出格式或远程采集能力。
- 只读取 parser 已归一化进 `details` 的稳定字段，不从 message/raw_line 中猜测上下文。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_alert_evidence_includes_normalized_context`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 alert evidence context 定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，50 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，194 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：包含 `device_name=FW-EDGE-01 policy_name=Allow-RDP src_zone=untrust dst_zone=server srcintf=wan1 dstintf=dmz1 vdom=root` 的 P0 防火墙事件会触发 `P0-FW-001`，但告警 evidence 只有事件数、IP、主机/目标、示例，缺少这些稳定上下文。
- 已新增 P0 聚合告警上下文摘要，将设备、策略/签名、风险分类、网络区域、接口、租户/虚拟域、会话和追踪 ID 从 `details` 汇总到 `DetectionAlert.evidence`。
- evidence 中新增的上下文会通过既有输出层清洗进入 HTML/JSON/CSV/SARIF/终端报告；告警触发条件、严重级别、MITRE、incident 关联和远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Network Context Normalization

### 本轮目标
- 修复 P0 防火墙/代理等日志中 `src_zone` / `dst_zone` / `srcintf` / `dstintf` / `vdom` 等网络上下文字段只保留压缩原始键，缺少稳定取证字段的问题。
- 提升 JSON/API/incident 二次处理对网络区域、入出接口、租户/虚拟域的可读性，便于 SOC 复核策略路径和资产边界。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只新增/填充 P0 `details.source_zone`、`details.destination_zone`、`details.source_interface`、`details.destination_interface`、`details.tenant` 稳定字段，不改变事件 `host`、`asset`、告警规则、事件级别、输出格式或远程采集能力。
- 只从明确的 zone/interface/tenant/vdom 字段归一化，不从 message/raw_line 中猜测网络上下文。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_network_context_preserves_zone_interface_and_tenant_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 network context 稳定字段定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，49 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，193 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：防火墙日志 `src_zone=untrust dst_zone=server srcintf=wan1 dstintf=dmz1 vdom=root` 会保留 `details.srczone` / `details.dstzone` / `details.srcintf` / `details.dstintf` / `details.vdom`，但稳定字段 `details.source_zone` / `details.destination_zone` / `details.source_interface` / `details.destination_interface` / `details.tenant` 均为空。
- 已新增 `_normalized_source_zone`、`_normalized_destination_zone`、`_normalized_source_interface`、`_normalized_destination_interface`、`_normalized_tenant`，将常见 zone/interface/tenant/vdom 字段归一化到稳定 details 字段。
- 原始归一化键仍保留在 `details` 中，便于溯源；事件 `host`、`asset`、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Vendor Rule Metadata Normalization

### 本轮目标
- 修复 P0 WAF/防火墙/代理/EDR 等日志中策略、签名、规则元数据只保留压缩原始键，缺少稳定取证字段的问题。
- 提升 JSON/API/incident 二次处理对厂商策略名、策略 ID、签名名、签名 ID 的可读性和可检索性。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只新增/填充 P0 `details.policy_name`、`details.policy_id`、`details.signature_name`、`details.signature_id` 稳定字段，不改变事件 `rule_id`、告警规则、事件级别、输出格式或远程采集能力。
- 只从明确的 policy/rule/signature 字段归一化，不从 message/raw_line 中猜测厂商规则元数据。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_vendor_rule_metadata_preserves_policy_and_signature_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 vendor rule metadata 稳定字段定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，48 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，192 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：WAF 日志 `policy_name=Block-SQLi policy_id=POL-42 signature_name="SQLi UNION" signature_id=SIG-9` 会保留 `details.policyname` / `details.policyid` / `details.signaturename` / `details.signatureid`，但稳定字段 `details.policy_name` / `details.policy_id` / `details.signature_name` / `details.signature_id` 均为空。
- 已新增 `_normalized_policy_name`、`_normalized_policy_id`、`_normalized_signature_name`、`_normalized_signature_id`，将常见 policy/rule/signature 字段归一化到稳定 details 字段。
- 原始归一化键仍保留在 `details` 中，便于溯源；事件 `rule_id`、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Device Name Normalization

### 本轮目标
- 修复 P0 防火墙/代理/VPN 等日志中 `devname` / `device_name` / `gateway` / `sensor_name` 等设备来源字段只保留原始键、没有稳定字段的问题。
- 提升 JSON/API/incident 二次处理对来源设备、防火墙网关、采集传感器的取证可读性。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只新增/填充 P0 `details.device_name` 稳定字段，不改变事件 `host`、`asset`、告警规则、事件级别、输出格式或远程采集能力。
- 只从明确的设备/网关/传感器字段归一化，不从 message/raw_line 中猜测设备来源。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_device_name_accepts_common_vendor_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 device name 稳定字段定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，47 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，191 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：代理日志 `devname=FW-EDGE-01` 会保留 `details.devname`，但 `details.device_name` 为空，稳定取证字段缺失。
- 已新增 `_normalized_device_name`，将 `device_name`、`devname`、`device`、`gateway`、`appliance_name`、`sensor_name` 等厂商设备字段归一化到稳定字段 `details.device_name`。
- 原始归一化键仍保留在 `details` 中，便于溯源；事件 `host`、`asset`、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。

## 2026-05-29 - P0 Risk Category Normalization

### 本轮目标
- 修复 P0 代理/DNS 等事件已用 `url_category` / `threat_category` / `classification` 等厂商字段触发检测，但没有统一稳定字段承载风险分类的问题。
- 提升 JSON/API/incident 二次处理对恶意分类、C2 分类、风险 verdict 的取证可读性。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只新增/填充 P0 `details.risk_category` 稳定字段，不改变告警规则、事件级别、MITRE 映射、输出格式或远程采集能力。
- 只从明确的分类/判定字段归一化，不从 message/raw_line 中猜测风险分类。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_risk_category_preserves_vendor_classification`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 risk category 稳定字段定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，46 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，190 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：代理日志 `url_category=Malware threat_category=C2` 会产出 “代理命中恶意分类” 事件，但 `details.risk_category` 为空，只能从原始归一化键 `urlcategory` / `threatcategory` 中取值。
- 已新增 `_normalized_risk_category`，将 `threat_category`、`risk_category`、`security_category`、`url_category`、`domain_category`、`query_category`、`dns_category`、`classification`、`verdict` 等厂商分类字段归一化到稳定字段 `details.risk_category`。
- 原始归一化键仍保留在 `details` 中，便于溯源；事件构建、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续审计 P0 稳定字段，例如设备名称、流量方向别名、URL path/query 组合与厂商字段的覆盖。

## 2026-05-29 - P0 Session Trace Alias Coverage

### 本轮目标
- 修复 P0 常见厂商字段 `flow_id` / `connection_id` / `transaction_id` 没有进入稳定字段 `details.session_id` / `details.trace_id` 的问题。
- 提升 incident/correlation/API 二次处理对同一会话、连接、请求链路的关联能力。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只补齐 P0 `details.session_id` / `details.trace_id` 的别名归一化，不改变告警规则、事件级别、MITRE 映射、输出格式或远程采集能力。
- 只把明确表示会话/连接/请求/事务 ID 的字段归一化到稳定字段，不从 message/raw_line 中猜测 ID。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_session_and_trace_accept_flow_and_transaction_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 session/trace 别名定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，45 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，189 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：代理/防火墙厂商日志中 `flow_id` / `transaction_id` 会保留为原始归一化键，但稳定字段 `details.session_id` / `details.trace_id` 为空，incident/correlation 下游无法直接使用这些链路 ID。
- 已将 `flow_id`、`connection_id`、`conn_id` 等连接/会话别名归一化到稳定字段 `details.session_id`。
- 已将 `transaction_id`、`tx_id`、`span_id`、`correlation_id` 等请求/事务链路别名归一化到稳定字段 `details.trace_id`。
- 原始归一化键仍保留在 `details` 中，便于溯源；事件构建、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续审计 P0 稳定字段，例如 URL 分类、风险分类、设备名称、流量方向别名与厂商字段的覆盖。

## 2026-05-29 - P0 Normalized Asset Alias Coverage

### 本轮目标
- 修复 P0 事件已在 `event.host` 或厂商目标字段中保留资产/目标，但稳定字段 `details.asset` 仍为空的问题。
- 提升 JSON/HTML/SARIF/incident/API 二次处理中的资产证据完整性，让 parser 产出的稳定字段更贴近现场研判语义。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只补齐 P0 `details.asset` 的别名归一化和防火墙目标 IP fallback，不改变告警规则、事件级别、MITRE 映射、输出格式或远程采集能力。
- 资产归一化优先使用显式资产/目标字段；仅在防火墙等明确目标语义来源中使用 `dst_ip` fallback，避免把无关字段误当资产。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_asset_uses_target_aliases_and_dst_ip_fallback`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 normalized asset 别名与防火墙 `dst_ip` fallback 定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，44 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，188 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：防火墙日志 `dst_ip=10.0.0.9` 能产出事件并设置 `event.host=10.0.0.9`，但 `details.asset` 为空；代理日志 `destination_host=beacon.evil.example` 能设置事件目标，但 `details.asset` 为空。
- 已新增来源感知的 `_normalized_asset`，将 `target_asset`、`dest_host`、`destination_host`、目标域名、`client_host` 等常见目标/资产别名统一到稳定字段 `details.asset`。
- 防火墙来源在没有显式资产字段时，会用 `dst_ip` 作为资产 fallback，使事件 host、incident 资产和 JSON 稳定字段保持一致。
- 代理来源会保留 `destination_host` / 目标域名到 `details.asset`，便于 JSON/API/incident 二次处理按目标聚合。
- 事件构建、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续审计 P0 稳定字段，例如 URL 分类、会话 ID、trace/request ID 和不同厂商流量方向字段的归一化覆盖。

## 2026-05-29 - P0 Normalized Action Alias Coverage

### 本轮目标
- 修复 P0 事件已经能用 `event_action` / `result` 等动作别名触发检测，但稳定字段 `details.action` 仍为空的问题。
- 提升 JSON/HTML/SARIF/incident 下游证据质量，让 parser 产出的规范化字段与事件判定语义一致。
- 保持 parser 只负责把结构化日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只补齐 P0 `details.action` 的别名归一化，不改变告警规则、事件级别、MITRE 映射、输出格式或远程采集能力。
- `result` / `outcome` 只在防火墙和代理这类常把动作写入结果字段的来源中作为 action 候选，避免把 VPN/应用的认证状态无差别写成动作。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_normalized_action_accepts_event_action_and_result_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 normalized action 别名定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，43 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，187 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：防火墙日志 `event_action=allow` 能产出“防火墙放行敏感端口访问”事件，事件 message 中 action 为 allow，但 `details.action` 为空，只能在原始归一化键 `eventaction` 中看到值。
- 已新增来源感知的 `_normalized_action`，统一 `event_action`、`rule_action`、`session_action`、`action_type`、`operation_type` 等动作别名到稳定字段 `details.action`。
- 防火墙/代理来源中，`result` / `outcome` 会作为 action 候选，覆盖常见厂商把 allow/deny 写入结果字段的导出格式。
- VPN 等认证类来源仍把 `result` 保留在 `details.status`，避免把登录失败/成功状态误写成动作字段。
- 事件构建、告警规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续审计 `details` 中其它稳定字段与 builder 语义不一致的别名，例如不同厂商对资产、会话、URL 分类字段的写法。

## 2026-05-29 - P0 Address-Style Firewall Auto Detection

### 本轮目标
- 修复 P0 自动识别对 `SourceAddress` / `DestinationAddress` / `DestinationPort` 这类地址风格字段不够敏感的问题，避免泛文件名 CSV 落到 generic parser。
- 让 P0 can_parse 与字段归一化保持一致：parser 已能消费 address-style 字段时，ParserRegistry 自动选择也应识别。
- 保持 CLI/pipeline/parser/detector/output/remote 架构边界不变；本轮只增强 parser 识别入口和回归覆盖。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只补充 P0 字段 hint，不改变事件构建、检测规则、correlation、输出格式或远程采集能力。
- 仍要求结构化样本命中多个 P0 字段，降低普通业务 CSV/JSON 被过度识别为 P0 的风险。
- 不引入联网、不上传日志、不依赖 CDN、不修改远端状态。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_auto_detects_address_style_firewall_csv`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 address-style 防火墙 CSV 自动识别定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，42 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，186 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：`events.csv` 这类泛文件名中包含 `SourceAddress,DestinationAddress,DestinationPort,Action,Protocol` 防火墙记录时，ParserRegistry 自动识别会落到 generic parser，产生通用事件而非 P0 防火墙事件。
- 已将 P0 字段 hint 扩展到常见 address-style 防火墙导出字段：`source_address`、`destination_address`、`destination_port` 以及策略动作类字段。
- 新增回归测试确认泛文件名 CSV 会自动识别为 P0 Security Log，并产出“防火墙放行敏感端口访问”事件，保留 src/dst/action 等规范化 detail。
- 事件构建、检测规则、correlation、输出格式、远程只读边界均未改变。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续还可以继续基于真实厂商样本补字段同义词；新增 hint 仍应坚持多字段命中门槛，避免普通业务 CSV/JSON 被过度识别为 P0。

## 2026-05-29 - P0 CamelCase Auto Detection

### 本轮目标
- 修复 P0 自动识别对 camelCase 厂商字段不够敏感的问题，避免 `srcIp` / `dstIp` / `logType` / `policyAction` 这类常见 JSON/CSV 导出在泛文件名下掉到 generic parser。
- 让自动识别与 P0 字段归一化保持一致：既然 parser 已经能消费 compact key，就不应在 can_parse 阶段漏掉。
- 保持 ParserRegistry 继续负责 parser 选择，P0 parser 只负责把结构化日志转成 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只增强 P0 can_parse 的字段 hint 计数，不改变事件构建、告警检测、CSV/JSON/JSONL/key=value 解析语义。
- 仍要求结构化样本至少命中多个 P0 字段 hint，避免把普通 JSON 文本过度吸入 P0 parser。
- 不引入联网、不上传日志、不修改远程只读采集边界。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_auto_detects_camelcase_vendor_fields`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 camelCase 自动识别定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，41 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，185 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：`events.json` 这类泛文件名中包含 `logType/srcIp/dstIp/dstPort/policyAction` camelCase 防火墙记录时，ParserRegistry 自动识别会落到 generic parser，产生通用事件而非 P0 防火墙事件。
- 已新增 `_p0_field_hint_hits`，字段 hint 同时按原始小写文本和 `_norm_key` compact key 匹配，使 can_parse 与 P0 字段归一化规则一致。
- `_looks_like_csv_header` 也复用同一 hint 计数逻辑，覆盖 camelCase CSV 表头。
- 新增回归测试确认泛文件名 JSON 自动识别为 P0 Security Log，并产出“防火墙放行敏感端口访问”事件。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可基于真实厂商样本继续补充字段同义词，但应避免把普通业务 JSON 过度识别为 P0；保持多字段命中门槛。

## 2026-05-29 - P0 JSON Wrapper Content Parsing

### 本轮目标
- 修复 P0 JSON wrapper 只在文件流式入口支持、在 `parse_p0_security_json()` / ParserRegistry `parse_content` 内存入口不展开的问题。
- 让 `{"records":[...]}` / `{"events":[...]}` 等已支持 wrapper 在远程采集、单元集成和内存内容解析路径中与文件路径行为一致。
- 保持 parser 只把日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只复用现有 `_json_value_records` wrapper 展开逻辑，不新增 P0 格式、不改变 CSV/JSONL/key=value 语义。
- 文件入口仍保持上一轮的流式 wrapper 解析；内存入口本身已经持有完整 content，不引入新的整文件读取路径。
- 不引入联网、不上传日志、不修改远程只读采集边界。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_wrapper_content_is_supported`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 wrapper 内存内容解析定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，40 个 P0 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，184 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：同一份 `{"events":[...]}` / `{"records":[...]}` P0 wrapper，文件入口可以解析为事件，但 `parse_p0_security_json()` 和 ParserRegistry `parse_content(..., parser_name="p0-security")` 返回 0 事件且无 parse error。
- 已让 `parse_p0_security_json()` 复用现有 `_json_value_records`，使内存 JSON 入口与文件入口共享已支持 wrapper key 的展开语义。
- 文件流式入口、JSONL、JSON array、CSV、key=value 行解析均不改变。
- 新增回归测试同时覆盖 direct JSON content 入口和 ParserRegistry `parse_content` 显式 P0 入口。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 内存内容入口仍然天然持有完整字符串，不作为大文件推荐路径；大文件继续优先走 `parse_p0_security_json_file()` 的流式入口。

## 2026-05-29 - SARIF MITRE Help URI Sanitization

### 本轮目标
- 修复 SARIF `helpUri` 直接拼接 `alert.mitre_attack` 的问题，避免恶意 MITRE 字段把 secret 或终端控制序列写入 SARIF。
- 让 SARIF 只为标准 ATT&CK technique ID 生成官方链接，异常/复合/非标准值保留在已清洗的 properties 中，不生成不合规 URI。
- 保持 output 只负责报告生成，不改变 parser/detector/correlation/remote 边界。

### 涉及模块
- `bla/output/sarif_report.py`
- `tests/test_outputs.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只收紧 SARIF rule `helpUri` 的生成条件，不改变告警规则 ID、结果内容、证据、affected_events 或 SARIF schema 版本。
- 标准 `T1234` / `T1234.001` 继续生成 attack.mitre.org 链接；非标准值只作为已清洗文本留在 `properties.mitre_attack`。
- 不引入联网、不依赖 MITRE 在线查询、不上传日志、不影响 HTML/JSON/CSV/IOC/manifest 输出。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_sarif_rejects_untrusted_mitre_help_uri`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- SARIF MITRE help URI 定点回归通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，34 个 output 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，183 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：恶意 `alert.mitre_attack` 形如 `T1059.access_token=super-secret` 加 OSC 控制序列时，SARIF rule `helpUri` 会直接拼出包含原始 secret 和控制 payload 的 URI。
- 已新增 `_mitre_help_uri`，先清洗文本，再只接受标准 `T1234` / `T1234.001` technique ID；非标准、复合或恶意值不生成 `helpUri`。
- 标准 ATT&CK technique 仍生成 `https://attack.mitre.org/techniques/Txxxx[/xxx]` 链接；非标准值仍以已清洗文本保留在 `properties.mitre_attack`，便于人工排查。
- 新增回归测试覆盖安全 technique 链接保留、恶意 MITRE 字段不进 `helpUri`，并断言 SARIF JSON 不包含 ESC/BEL、OSC payload 或原始 secret。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续可继续审计 SARIF/manifest/JSON 中其它 URI/ID 类字段，但应保持“先复现、再最小修复、再回归”的节奏，避免不必要的格式变化。

## 2026-05-29 - Structured IOC Value Sanitization

### 本轮目标
- 修复 `extract_iocs()` 返回的结构化 IOC 字典仍可能保留 URL/命令中的 secret 或终端控制序列的问题。
- 确保 IOC 在文本导出前的内存结构也满足脱敏边界，避免后续 JSON/API/工单集成复用时泄漏敏感值。
- 保持 IOC 只从事件和告警证据中提取可研判对象，不改变 parser/detector/correlation/remote 边界。

### 涉及模块
- `bla/ioc.py`
- `tests/test_outputs.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只在 IOC 返回值出口做清洗，不改变 IOC 匹配正则、告警相关事件筛选或检测结果。
- URL、命令、用户、进程、路径等 IOC 值中的 obvious secret 会脱敏；IP、域名、hash 等正常值保持稳定。
- 不引入联网、不依赖外部信誉服务、不上传日志、不修改报告文件结构。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_extract_iocs_returns_sanitized_values`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- 结构化 IOC 值脱敏定点回归通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，33 个 output 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，182 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- 已复现问题：`format_ioc_report()` 会清洗文本导出，但 `extract_iocs()` 返回的结构化 IOC 字典仍可能包含 `access_token=super-secret` 和 OSC 控制序列。
- 已将 `extract_iocs()` 的返回出口改为统一调用 `sanitize_report_text`，让 URL、命令、用户、进程、路径等 IOC 值在进入文本导出或下游集成前就完成控制字符清理和 obvious secret 脱敏。
- 现有 IOC 匹配、告警相关事件过滤、IP/域名/hash 正常提取语义保持不变。
- 新增回归测试断言结构化 IOC 字典不包含 ESC/BEL、OSC payload 或原始 secret，并保留 `access_token=<redacted>`、`token=<redacted>` 与正常域名。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续可继续审计 SARIF/manifest/JSON 中第三方消费端会直接读取的 ID 类字段，但需逐项用恶意文本样本证明风险后再改。

## 2026-05-29 - P0 Streaming JSON Wrapper Records

### 本轮目标
- 强化 P0 JSON wrapper 文件的大文件稳定性，让顶层 `records` / `events` / `logs` / `items` / `data` 数组按元素流式展开。
- 保留错误输入中的已解析前序事件，避免 wrapper 数组后段损坏导致整份文件无事件。
- 保持 parser 只把日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只处理顶层 JSON object 中已支持的 wrapper 数组键，不改变普通 JSONL、JSON array、CSV、key=value 语义。
- 文件入口继续使用 `iter_file_chunks`，不引入默认联网、不上传日志、不新增依赖。
- wrapper 中的其他 metadata 只用于跳过或定位数组，不进入告警语义，避免污染事件。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_wrapper_keeps_partial_events_and_counts_decode_error tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_wrapper_records_file_is_supported tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_array_file_streams_records tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_sequence_without_array_still_parses`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 bla_cli.py benchmark --size-mb 1`
- `python3 bla_cli.py benchmark --size-mb 1 --memory`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 wrapper 流式错误保留、既有 wrapper 文件、JSON array 流式、JSON sequence 兼容定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，39 个 P0 回归用例通过。
- `python3 bla_cli.py benchmark --size-mb 1` 通过，1.00 MB / 6833 events / 0.414s / 2.42 MB/s。
- `python3 bla_cli.py benchmark --size-mb 1 --memory` 通过，1.00 MB / 6833 events / peak memory 32.91 MB。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，181 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- P0 JSON 顶层 wrapper key `events` / `records` / `logs` / `items` / `data` 中的数组现在按元素流式展开，不再为了读取 wrapper 先整对象解码。
- wrapper 数组后段损坏时，已解析的前序事件会保留，并把损坏位置计入 `parse_errors`，方便大文件排障。
- 普通 JSON array 的严格逗号校验、JSONL/连续 JSON object sequence、CSV、key=value 兼容性保持不变。
- 新增回归测试覆盖畸形 wrapper 数组保留首条事件并记录 decode error，同时复跑既有 wrapper/array/sequence 场景防止回退。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续如遇到真实厂商样本把大数组深埋在多层 wrapper 或未知 key 中，可再做基于样本的流式展开；当前先限制在已支持的顶层 wrapper key，避免过度猜测格式。

## 2026-05-29 - P0 Streaming JSON Array Strictness

### 本轮目标
- 强化 P0 JSON 文件流式解析的错误输入处理，避免畸形 JSON 数组在元素缺逗号时被宽松解析为合法事件序列。
- 保持 JSONL/连续 JSON 对象导出的兼容性，不为了严格数组而破坏常见厂商逐行对象格式。
- 保持 parser 只把日志转为 `LogEvent`，不改变 detector/correlation/output/remote 边界。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只收紧以 `[` 开头的 JSON array 模式；非数组 JSONL/连续 JSON 对象仍按 sequence 模式解析。
- 文件入口继续使用 `iter_file_chunks` 流式读取，不引入整文件读入，不新增依赖。
- 不引入联网、不上传日志、不修改远程采集能力。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_array_requires_commas_between_records tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_json_sequence_without_array_still_parses`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 bla_cli.py benchmark --size-mb 1`
- `python3 bla_cli.py benchmark --size-mb 1 --memory`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- P0 JSON array strictness 与 JSON sequence 兼容定点回归通过。
- `python3 -m pytest -q tests/test_p0_security.py` 通过，38 个 P0 回归用例通过。
- `python3 bla_cli.py benchmark --size-mb 1` 通过，1.00 MB / 6833 events / 0.378s / 2.64 MB/s。
- `python3 bla_cli.py benchmark --size-mb 1 --memory` 通过，1.00 MB / 6833 events / peak memory 32.91 MB。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，180 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- P0 JSON array 模式现在在元素之间严格要求逗号，遇到缺逗号、前导逗号或尾随逗号会计入 JSON decode error，并保留已解析的前序事件。
- JSONL/连续 JSON 对象仍按 sequence 模式解析，不受 array 分隔符收紧影响。
- 新增回归测试覆盖畸形数组 `[{} {}]` 只保留已解析事件并记录 `parse_errors=1`，以及非数组 JSON sequence 仍解析两条事件。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- JSON wrapper 中超大 `records` 列表仍会随单个 wrapper 对象一起解码；若后续遇到超大包装对象样本，可再做专门的 wrapper 流式展开优化。

## 2026-05-29 - Windows Persistence Baseline Hints

### 本轮目标
- 降低 Windows 原生维护类服务/计划任务被 generic 持久化告警按同等置信度处置的误报风险。
- 对明显 Windows 维护基线特征增加低强度证据提示，同时保留原始事件和通用持久化告警，避免静默漏报。
- 保持 parser 只做字段归一化/分类，detector 只根据事件生成告警，不改变 CLI/pipeline/output/remote 边界。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮不删除 7045/4698 事件，不跳过告警，只对明确维护基线降低 confidence 并加入人工复核提示。
- 一旦执行内容命中 PowerShell encoded、下载执行、LOLBins 等高危特征，仍由 `suspicious-persistence` 覆盖为高强度证据。
- 不引入联网、不依赖外部信誉服务、不修改远程采集能力。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_maintenance_service_install_gets_low_strength_hint tests/test_detection.py::DetectionRegressionTests::test_windows_maintenance_task_has_low_confidence_persistence_alert`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- Windows 维护服务/计划任务定点回归通过。
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py` 通过，确认既有高危持久化、Sysmon C2、凭据访问回归未受影响。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，178 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- Windows 7045 服务安装会对明确 Windows 维护服务名、系统服务账号、System32/Servicing 原生执行路径组合标注 `persistence_baseline=windows-maintenance-service`。
- Windows 4698 计划任务会对 UpdateOrchestrator/WindowsUpdate/Defender/WaaSMedic 维护任务、系统账号、原生维护程序组合标注 `persistence_baseline=windows-maintenance-task`。
- `detect_persistence` 保留 `PERS-001` / `PERS-002` 告警和原始事件，但对维护基线候选使用 low confidence，并把基线候选与复核提示写入证据。
- 高危执行内容仍优先覆盖：PowerShell encoded、下载执行、LOLBins 等会清除低风险提示并进入 `suspicious-persistence` / `PERS-004`。
- 新增回归测试覆盖维护服务与维护计划任务，确认低置信度提示不会误伤高危持久化检测。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续可继续扩展维护基线，但应以真实客户日志或明确 Windows 事件样本为依据，避免过度白名单导致漏报。

## 2026-05-29 - Structured Output Key Sanitization

### 本轮目标
- 强化 JSON、manifest、SARIF 等结构化输出的清洗边界，覆盖攻击者可控的字典 key 和事件引用字段。
- 防止日志 details key、manifest context key、SARIF affected_events 中的终端控制字符或 secret 绕过 value 侧清洗。
- 保持 output 只负责生成离线报告，不改变 parser/detector/correlation/remote 边界。

### 涉及模块
- `bla/output/json_report.py`
- `bla/output/manifest.py`
- `bla/output/sarif_report.py`
- `tests/test_outputs.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只修改报告序列化前的文本清洗，不改变分析结果、检测逻辑、CLI 参数或远程采集行为。
- 正常字符串 key 保持可读；命中控制字符或明显 secret 赋值的 key 会被剥离/脱敏。
- 不引入联网、CDN、日志上传或新增依赖。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_structured_outputs_sanitize_attacker_controlled_keys_and_refs`
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_sarif_remote_artifact_uri_sanitizes_path`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`
- `git diff --check`

### 验证结果
- 新增结构化输出 key/ref 清洗与 SARIF remote artifact URI 清洗回归用例通过。
- `python3 -m pytest -q tests/test_outputs.py` 通过，32 个 output 回归用例通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，176 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- `git diff --check` 通过。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- JSON 报告递归清洗字典 key，覆盖 `LogEvent.details` 等攻击者可控字段名。
- manifest 递归清洗字典 key，覆盖 `context.options` 等外部传入上下文字段名。
- SARIF `properties.affected_events` 和 remote artifact URI 路径段现在会清洗控制字符并脱敏明显 secret。
- 新增回归测试确认 JSON details key、manifest options key、SARIF affected_events、SARIF remote artifact URI 不保留 OSC/CSI 控制序列、base64 OSC 载荷或 `token=super-secret` 原文。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续审计 JSON/CSV/IOC/SARIF 中更深层的派生字段，例如 incident/timeline 的 ID 类字段和第三方消费端兼容性。

## 2026-05-29 - Windows Persistence Evidence Hardening

### 本轮目标
- 增强 Windows 7045 服务安装与 4698/4702 计划任务事件的字段归一化和证据质量。
- 对计划任务或服务中嵌入 PowerShell/LOLBins/下载执行等高危命令的持久化行为生成更明确的检测证据。
- 保持 parser 只转换事件、detector 只生成告警，不改变 CLI/pipeline/output/remote 边界。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只处理 Windows 服务安装和计划任务事件中的本地日志字段，不做远端采集，不做联网情报查询。
- 普通服务安装/计划任务仍保留既有告警；只有命中明确高危命令或 LOLBins 特征时才增加 `suspicious-persistence` 证据标签。
- 不扩大中央 if/elif parser 分发，不改变流式 XML 文件解析路径。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_service_install_normalizes_suspicious_image_path tests/test_detection.py::DetectionRegressionTests::test_scheduled_task_persistence_command_creates_high_risk_alert tests/test_detection.py::DetectionRegressionTests::test_benign_sysmon_network_dns_do_not_create_c2_alert tests/test_detection.py::DetectionRegressionTests::test_suspicious_sysmon_dns_creates_c2_alert_not_p0_alert`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点 Windows 持久化/Sysmon C2 回归通过。
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py tests/test_p0_security.py` 通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，174 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- Windows 7045 服务安装现在归一化 `service_name`、`service_image_path`、`service_account`、`persistence_command`、`child_process` 等字段。
- Windows 4698/4702 计划任务现在从 `TaskContent` 中提取 `task_command`、`task_arguments` 和 `persistence_command`。
- 服务或计划任务中的 PowerShell encoded command、下载执行、LOLBins 等高危执行内容会被标记为 `suspicious-persistence`，并保留在持久化语义下。
- `detect_persistence` 增加 `PERS-004` 高危持久化执行内容告警，同时增强 `PERS-001` / `PERS-002` 的执行命令证据。
- 新增回归测试覆盖恶意服务 ImagePath 和高危计划任务 TaskContent，确认告警、证据和攻击链阶段稳定。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续补强服务/计划任务的误报抑制，例如签名路径、系统更新任务基线和变更窗口上下文。

## 2026-05-29 - Sysmon C2 Alerting Noise Reduction

### 本轮目标
- 降低 Sysmon 3/22 普通网络与 DNS 事件被默认映射为命令控制的误报风险。
- 对命中明确可疑域名/回连域名特征的 Sysmon DNS/网络事件生成专门 C2 外联告警。
- 保持 detector 通过 `DetectorRegistry` 注册并使用 selector 预筛，不引入多轮全量扫描。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只调整 Sysmon 网络/DNS 的默认语义和告警聚合，不改变 CLI、pipeline、output 或 remote 边界。
- 普通 Sysmon 3/22 保留为事件，不默认打 `T1071`；只有命中可疑域名/回连特征时才进入 C2 检测链路。
- 不引入联网、外部情报查询或日志上传；可疑域名判断只基于离线正则。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_sysmon_network_and_dns_fields_are_normalized tests/test_detection.py::DetectionRegressionTests::test_benign_sysmon_network_dns_do_not_create_c2_alert tests/test_detection.py::DetectionRegressionTests::test_suspicious_sysmon_dns_creates_c2_alert_not_p0_alert tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_dns_vendor_category_fields_promote_c2_alert`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点 Sysmon/P0 回归通过。
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py tests/test_p0_security.py` 通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，172 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- 本轮未运行 `scripts/release_check.py --build`，未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- Sysmon 3/22 普通网络/DNS 事件不再默认带 `T1071` / `T1071.004`，避免普通外联直接进入命令控制语义。
- 可疑 Sysmon DNS/网络事件命中离线域名特征后，会打 `c2` / `malicious-domain` / `callback-domain`，并进入新增的 `sysmon-command-control` detector。
- 新增 `C2-001` 告警，用 `DetectorRegistry` 注册并通过 selector 预筛 Sysmon 3/22 与 C2 标签事件。
- `P0-C2-001` 聚合现在只处理带 `p0_kind` 的 P0 结构化事件，避免 Sysmon C2 被误归入 P0 告警。
- 新增回归测试覆盖普通 Sysmon 网络/DNS 不产生 C2 告警，以及可疑 Sysmon DNS 产生 `C2-001` 而不是 `P0-C2-001`。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续可继续细化 Sysmon 公网 IP 外联、LOLBins 出站连接和 DNS 隧道启发式，但需要谨慎控制误报。

## 2026-05-29 - Windows Sysmon Credential Dump Classification

### 本轮目标
- 增强 Windows 4688 与 Sysmon 1 进程创建日志对凭据转储命令的分类质量。
- 让 procdump/rundll32 comsvcs/reg save/ntdsutil 等真实蓝队常见凭据访问痕迹进入 `credential-access` 检测链路，而不只停留在通用可疑执行。
- 保持 XML 解析流式边界，不增加默认联网行为，不改变输出和 remote 安全边界。

### 涉及模块
- `bla/parsers/windows_evtx.py`
- `tests/test_parsers.py`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只在 parser 内补充字段归一化和 tag/level 分类，不在 detector 中做多轮全量扫描，不改变 pipeline 编排。
- 不改变 4688 普通进程创建的低噪声行为；只有命中明确凭据转储命令特征时才升级为凭据访问。
- 不引入默认联网、不上传日志、不让 HTML 依赖 CDN，不修改 remote 模块。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_4688_credential_dump_command_feeds_credential_detector tests/test_parsers.py::ParserRegressionTests::test_sysmon_process_creation_normalizes_and_detects_reg_save`
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_sysmon_network_and_dns_fields_are_normalized tests/test_parsers.py::ParserRegressionTests::test_windows_4688_process_creation_is_not_generic_t1059 tests/test_parsers.py::ParserRegressionTests::test_windows_4688_credential_dump_command_feeds_credential_detector tests/test_parsers.py::ParserRegressionTests::test_sysmon_process_creation_normalizes_and_detects_reg_save`
- `python3 -m pytest -q tests/test_parsers.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_windows_4688_credential_dump_command_feeds_credential_detector tests/test_parsers.py::ParserRegressionTests::test_sysmon_process_creation_normalizes_and_detects_reg_save` 通过。
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_sysmon_network_and_dns_fields_are_normalized tests/test_parsers.py::ParserRegressionTests::test_windows_4688_process_creation_is_not_generic_t1059 tests/test_parsers.py::ParserRegressionTests::test_windows_4688_credential_dump_command_feeds_credential_detector tests/test_parsers.py::ParserRegressionTests::test_sysmon_process_creation_normalizes_and_detects_reg_save` 通过。
- `python3 -m pytest -q tests/test_parsers.py` 通过。
- `python3 -m compileall -q bla bla_cli.py setup.py tests` 通过。
- `python3 -m pytest -q` 通过。
- `python3 -m unittest discover -s tests -v` 通过，170 个测试通过。
- `python3 scripts/release_check.py` 通过，包含 `validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke。
- 本轮未运行 `scripts/release_check.py --build`，因为用户明确要求继续优化、发布前先汇报；本轮未打 tag、未发布 GitHub Release、未上传 PyPI。

### 修改结果
- Windows 4688 与 Sysmon 1 进程创建日志现在会将明确凭据转储命令分类为 `credential-access` / `credential-dump`，并按行为映射 MITRE：LSASS 内存转储 `T1003.001`，注册表 hive 保存 `T1003.002`，NTDS 导出 `T1003.003`。
- 新增 Sysmon 常用字段归一化：进程创建的 `parent_process`、`child_process`、`child_path`、`command_line`，网络连接的源/目的 IP 和端口，进程访问的源/目标进程，DNS 查询字段。
- Sysmon 3 网络连接现在按方向选择顶层 `event.ip`：出站连接使用目的 IP，入站连接使用来源 IP，避免本机 `SourceIp` 污染攻击源统计。
- 新增回归测试覆盖 Security 4688 `procdump lsass`、Sysmon 1 `reg save HKLM\SAM`、Sysmon 3/22 网络与 DNS 字段归一化，并确认新增凭据事件进入凭据访问 detector；保留普通 4688 不产生通用执行攻击链的低噪声行为。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 后续仍可继续补强 Windows/Sysmon 网络连接、DNS、服务安装和计划任务的字段归一化与更细粒度误报抑制。

## 2026-05-29 - v1.4.3 Release Closure

### 本轮目标
- 将已通过验证的 CLI、JSON 输出、输出安全、Shell 外传检测和 P0/HVV 字段兼容优化收口为 `v1.4.3`。
- 补齐发布说明、README 摘要和 release gate smoke，确保新能力进入发布前自动验证。
- 明确 `soft-copyright-materials/` 是本地软著材料，不进入 BLA 运行时代码或发布包。

### 涉及模块
- `bla/__version__.py`
- `README.md`
- `docs/releases/v1.4.3.md`
- `scripts/release_check.py`
- `.gitignore`
- `BLA_OPTIMIZATION_PLAN.md`

### 风险边界
- 本轮只做发布收口，不新增联网行为，不改变 HTML 离线交付边界。
- 不改变 remote 只读、白名单、超时、限量和审计边界。
- 不把本地软著材料纳入发布提交或包产物。

### 验证命令
- `python3 scripts/release_check.py --build`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 bla_cli.py validate-rules --strict-metadata`

### 验证结果
- `python3 scripts/release_check.py --build` 通过。
- 发布门禁已覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help`、1 MB benchmark、1 MB memory benchmark、样例报告 smoke、v1.4.1/v1.4.2/v1.4.3 smoke、wheel/sdist build 和 `twine check`。
- `python3 bla_cli.py --version` 输出 `BLA 1.4.3`。
- `git diff --check` 通过。
- GitHub Release 触发的 Publish workflow 已成功发布到 PyPI。
- 首次 push Tests workflow 在 Windows pytest 阶段失败，原因是测试 fixture 使用了 Windows 文件系统不允许的 ESC/BEL 路径名；已改为平台安全的恶意路径测试，并重新通过本地定点回归和 `release_check.py --build`。
- 修复后的 GitHub Tests workflow `26638972410` 已通过，覆盖 Ubuntu/macOS/Windows 与 Python 3.9-3.12。
- PyPI 干净虚拟环境安装验证通过：`blueteam-log-analyzer==1.4.3` 可安装，`bla --version` 输出 `BLA 1.4.3`，`validate-rules --strict-metadata`、`ssh --help`、`remote-log --help` 和样例分析均通过。

### 修改结果
- 已将版本号提升到 `1.4.3`。
- 已新增 `docs/releases/v1.4.3.md`，README 当前版本摘要改为 v1.4.3。
- 已将 `scripts/release_check.py` 增加 v1.4.3 冒烟场景，覆盖 JSON 事件限量、raw_line 限长、Shell 外传、Proxy/SWG `request_url`、Firewall `policy_action`、VPN `auth_result` 等链路。
- 已将 `soft-copyright-materials/` 加入 `.gitignore`，避免本地软著材料进入 BLA 发布提交或包产物。
- 已将终端清洗相关测试里的恶意文件名改为 Windows 可创建的路径片段，仍保留 secret 脱敏断言；非 Windows 平台继续覆盖 ESC/BEL 控制字符路径。

### 剩余问题
- `v1.4.3` 已发布；本轮未发现 P0/P1 已知问题。
- 历史中保留一次已修复的 Windows Tests 失败 run `26638772645`，后续 run `26638972410` 已通过。

## 2026-05-29 - P0 Proxy Vendor Request URL Fields

### 本轮目标
- 修复代理/SWG 日志中 URL 写在 `request_url` / `request_uri` 等厂商字段时，可执行/脚本下载不会生成事件的问题。
- 保留这类字段中的目标域名，避免恶意分类事件进入 `P0-C2-001` 时证据目标为空。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Proxy/SWG adapter 的 URL 字段别名和统一 `details.url` 归一；Detector 仍通过既有 selector 聚合。
- 不改变 proxy 大流量外发方向判定、WAF、DNS、firewall、EDR、bastion、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_proxy_vendor_request_url_fields_preserve_target_and_download_detection`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_proxy_vendor_request_url_fields_preserve_target_and_download_detection`。
- P0 回归通过：`tests/test_p0_security.py` 共 36 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=proxy request_url=https://download.evil.example/tool.ps1` 不生成下载事件；`request_url=https://beacon.evil.example/a url_category=Malware threat_category=C2` 生成事件但目标为空。
- 已将 Proxy/SWG adapter 的 URL 字段扩展到 `request_url/request_uri/full_url` 等常见厂商别名。
- 已让这些 URL 字段参与可疑 URL/脚本下载检测、目标域名提取和统一 `details.url` 归一。
- 已新增回归测试，覆盖 `request_url` 脚本下载事件、恶意分类事件目标域名保留、URL 归一和既有 `P0-C2-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的多文件改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Application Vendor Auth Result Fields

### 本轮目标
- 修复应用审计日志中认证结果写在 `auth_result` / `login_status` / `auth_status` 等厂商字段时，登录失败事件不生成的问题。
- 保留 `service_name` / `app_name` 这类业务服务字段，避免应用认证事件缺少业务系统上下文。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Application adapter 的认证结果、失败原因和服务名字段别名；Detector 仍通过既有 `failed-login` selector 聚合。
- 不改变 VPN、WAF、DNS、firewall、proxy、EDR、bastion、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_application_vendor_auth_result_fields_feed_brute_force_detection`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_application_vendor_auth_result_fields_feed_brute_force_detection`。
- P0 回归通过：`tests/test_p0_security.py` 共 35 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：5 条 `log_type=app event_type=login auth_result=failed service_name=portal` 登录失败不会生成事件，也不会触发 `BRUTE-001`。
- 已将 Application adapter 的认证结果字段扩展到 `auth_result/login_result/auth_status/login_status` 等常见厂商别名。
- 已将认证原因字段扩展到 `auth_reason/failure_reason`，并将业务上下文字段扩展到 `service_name/app_name/application_name`。
- 已新增回归测试，覆盖 5 次厂商字段应用登录失败事件生成、业务系统上下文、用户/IP 保留、`failed-login` 标签和既有 `BRUTE-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的多文件改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Bastion Vendor Operation Fields

### 本轮目标
- 修复堡垒机审计中 `operation_type=file_download/file_upload` 且无 `command` 字段时不会生成文件传输事件的问题。
- 保留 `target_asset` / `asset_name` 这类目标资产字段，避免堡垒机事件缺失目标主机。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Bastion adapter 的操作、文件和目标资产字段别名；Detector 仍通过既有 `bastion-command` selector 生成 `P0-BASTION-001`。
- 不改变 VPN、WAF、DNS、firewall、proxy、EDR、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_bastion_vendor_operation_type_file_transfer_is_detected`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_bastion_vendor_operation_type_file_transfer_is_detected`。
- P0 回归通过：`tests/test_p0_security.py` 共 34 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`type=bastion operation_type=file_download target_asset=10.0.0.5 file_name=/tmp/db.sql` 不生成事件，也不会触发 `P0-BASTION-001`。
- 已将 Bastion adapter 的操作字段扩展到 `action_type/event_action/operation_type/activity` 等常见厂商别名。
- 已将目标资产字段扩展到 `target_asset/asset_name/dst_ip/dest_ip` 等别名，并扩展文件字段到 `source_file/target_file`。
- 已新增回归测试，覆盖无 command 的厂商字段文件下载事件生成、目标资产保留、操作者保留、`file-transfer` 标签和既有 `P0-BASTION-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的多文件改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 VPN Vendor Auth Result Fields

### 本轮目标
- 修复 VPN/SSLVPN 日志中认证结果写在 `auth_result` / `login_status` / `auth_status` 等厂商字段时，登录失败事件不生成的问题。
- 让这类 VPN 失败继续通过既有 `failed-login` 标签进入 `BRUTE-001` / `SPRAY-001` 检测，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 VPN adapter 的认证结果和原因字段别名；Detector 仍通过既有 registry 和 `failed-login` selector 聚合。
- 不改变 WAF、DNS、firewall、proxy、EDR、bastion、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_vpn_vendor_auth_result_fields_feed_brute_force_detection`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_vpn_vendor_auth_result_fields_feed_brute_force_detection`。
- P0 回归通过：`tests/test_p0_security.py` 共 33 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：5 条 `log_type=vpn auth_result=failed` 登录失败不会生成事件，也不会触发 `BRUTE-001`。
- 已将 VPN adapter 的认证结果字段扩展到 `auth_result/login_result/auth_status/login_status` 等常见厂商别名。
- 已将 VPN 认证原因字段扩展到 `auth_reason/failure_reason` 等别名，保留失败原因上下文。
- 已新增回归测试，覆盖 5 次厂商字段登录失败事件生成、用户/IP 保留、`failed-login` 标签和既有 `BRUTE-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的多文件改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Firewall Vendor Action Fields

### 本轮目标
- 修复防火墙/NAT 日志中动作写在 `policy_action` / `event_action` / `rule_action` 等厂商字段时，敏感端口放行被降级为“动作未知”的问题。
- 保持 `action` 缺失时的保守中危判定，不把未知动作误报成放行。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Firewall/NAT adapter 的动作字段别名；Detector 仍通过既有 `exposed-service` selector 生成 `P0-FW-001`。
- 不改变 firewall 大流量外联、proxy/WAF/DNS/EDR、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_firewall_vendor_policy_action_fields_promote_exposed_service`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_firewall_vendor_policy_action_fields_promote_exposed_service`。
- P0 回归通过：`tests/test_p0_security.py` 共 32 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=firewall dst_port=3389 policy_action=allow` 被解析为 `防火墙敏感端口访问（动作未知）`，未带 `exposed-service`，也未触发 `P0-FW-001`。
- 已将 Firewall/NAT adapter 的动作字段扩展到 `policy_action/event_action/rule_action/session_action` 等常见厂商别名。
- 已新增回归测试，覆盖敏感端口放行、`exposed-service` 标签、归一化 action 保留和既有 `P0-FW-001` 告警聚合。
- 保留缺失动作字段时的 `防火墙敏感端口访问（动作未知）` 中危保守判定。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的多文件改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 WAF Vendor Request Fields

### 本轮目标
- 修复 WAF 日志中攻击 URI 和攻击名称写在 `request_uri` / `request_url` / `attack_name` 等厂商字段时被降级为普通拦截的问题。
- 保留 `src_addr` / `source_addr` 这类源地址字段，避免 WAF 事件缺失攻击源 IP。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 WAF adapter 的请求、攻击标签和源 IP 字段别名；Detector 仍通过既有 registry 和 `web-attack` selector 聚合。
- 不改变 DNS、proxy、EDR、firewall、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_waf_vendor_request_fields_preserve_sqli_and_source_ip`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_waf_vendor_request_fields_preserve_sqli_and_source_ip`。
- P0 回归通过：`tests/test_p0_security.py` 共 31 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=waf src_addr=203.0.113.8 request_uri="/login?id=1 UNION SELECT NULL--" attack_name="SQL Injection"` 被降级为 `WAF 拦截/告警`，且源 IP 为空。
- 已将 WAF adapter 的请求、攻击标签和路径字段扩展到常见厂商别名，包括 `request_uri/request_url/full_url/attack_name/attack_type/signature_name/rule_name/user_agent`。
- 已将统一源 IP 提取扩展到 `src_addr/source_addr/client_addr`。
- 已新增回归测试，覆盖 SQL 注入分类、源 IP 保留、`web-attack/blocked` 标签、攻击 URI 展示和厂商字段保留。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 DNS Vendor Category Fields

### 本轮目标
- 修复 DNS 安全日志中恶意分类写在 `threat_category` / `domain_category` / `query_category` 等厂商字段时不会生成 C2/恶意域名事件的问题。
- 让这类 DNS 命中继续通过既有 `c2` 标签进入 `P0-C2-001`，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 DNS adapter 的查询、分类、rcode 和响应 IP 字段别名；Detector 仍通过既有 registry 和 `c2/dns-tunnel` selector 聚合。
- 不改变 proxy、EDR、WAF、firewall、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_dns_vendor_category_fields_promote_c2_alert`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_dns_vendor_category_fields_promote_c2_alert`。
- P0 回归通过：`tests/test_p0_security.py` 共 30 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=dns query=beacon.evil.example threat_category=C2` 不生成事件，也不会触发 `P0-C2-001`。
- 已将 DNS adapter 的查询、分类、rcode 和响应 IP 字段扩展到常见厂商别名，包括 `dns_query/rrname/threat_category/domain_category/query_category/dns_category/response_code/resolved_ip/response_ip`。
- 已新增回归测试，覆盖 DNS 事件生成、源 IP 保留、`dns/c2` 标签、厂商分类字段保留和既有 `P0-C2-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 EDR Detection Name Fields

### 本轮目标
- 修复 EDR/XDR 结构化日志中凭据转储线索写在 `detection_name` / `process_name` / `technique_id` 等厂商字段时不会生成事件的问题。
- 让这类 EDR 告警继续通过既有 `edr/malware-indicator/lsass-dump` 标签进入 `P0-EDR-001` 和凭据访问检测，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 EDR/XDR adapter 的标题、文本、进程、命令和 MITRE 字段别名；Detector 仍通过既有 registry 和 selector 聚合。
- 不改变 WAF、VPN、proxy/firewall、bastion、application、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_edr_vendor_detection_fields_detect_credential_dumping`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_edr_vendor_detection_fields_detect_credential_dumping`。
- P0 回归通过：`tests/test_p0_security.py` 共 29 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=edr detection_name="Mimikatz credential dumping" process_name=mimikatz.exe technique_id=T1003.001` 不生成事件，也不会触发 EDR/P0 或凭据访问告警。
- 已将 EDR/XDR adapter 的标题、文本、进程、命令和 MITRE 字段扩展到常见厂商别名，包括 `detection_name/process_name/process_path/command_line/technique_id/mitre_id`。
- 已新增回归测试，覆盖 EDR 事件生成、CRITICAL 级别、MITRE 保留、进程字段保留、`malware-indicator/lsass-dump` 标签、既有 `P0-EDR-001` 和 `CRED-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Proxy Vendor Category Fields

### 本轮目标
- 修复代理/SWG 日志中恶意分类写在 `url_category` / `threat_category` 等厂商字段时不会生成 C2/恶意 URL 事件的问题。
- 让这类代理命中继续通过既有 `c2` 标签进入 `P0-C2-001`，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Proxy/SWG adapter 的分类文本字段归一化；Detector 仍通过既有 registry 和 `c2/dns-tunnel` selector 聚合。
- 不改变 proxy 大流量外发、下载可执行文件、WAF、firewall、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_proxy_vendor_category_fields_promote_c2_alert`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_proxy_vendor_category_fields_promote_c2_alert`。
- P0 回归通过：`tests/test_p0_security.py` 共 28 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=proxy url_category=Malware threat_category=C2` 不生成事件，也不会触发 `P0-C2-001`。
- 已将 Proxy/SWG adapter 的分类文本字段扩展到 `url_category/threat_category/risk_category/security_category/classification/verdict/disposition/policy/policy_action/rule/signature`。
- 已新增回归测试，覆盖事件字段、目标域名、`c2/malicious-url` 标签和既有 `P0-C2-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Application Auth Event Fields

### 本轮目标
- 修复应用 P0 结构化日志中 `event=login_failed` / `event_type=auth_failure` 放置认证结果时不会生成登录失败事件的问题。
- 让应用登录失败继续通过既有 `failed-login` 标签进入暴力破解/喷洒检测，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只扩展 Application adapter 的认证字段归一化；Detector 仍通过既有 registry 和 `failed-login` selector 聚合。
- 不改变 VPN、堡垒机、WAF、EDR、proxy/firewall、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_application_auth_event_field_feeds_brute_force_detection`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_application_auth_event_field_feeds_brute_force_detection`。
- P0 回归通过：`tests/test_p0_security.py` 共 27 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：5 条 `log_type=app event=login_failed` 应用登录失败不会生成事件，也不会触发 `BRUTE-001`。
- 已将 Application adapter 的认证文本字段扩展到 `event/event_type/event_name/operation/activity/reason`。
- 已新增回归测试，覆盖应用登录失败事件生成、`failed-login/application` 标签和既有 `BRUTE-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮不会回退或清理这些现场状态。

## 2026-05-29 - P0 Bastion File Transfer Without Command

### 本轮目标
- 修复堡垒机审计中 `operation=file_upload/file_download` 且没有 `command` 字段时不会生成 P0 文件操作事件的问题。
- 让这类文件传输事件继续通过既有 `P0-BASTION-001` 检测规则聚合，不新增 detector 分支。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- Parser 只把堡垒机文件操作归一为 `LogEvent`；Detector 仍通过现有 registry 和 `bastion-command` selector 生成告警。
- 不改变命令审计、高危命令、登录成功/失败、correlation、output 或 remote 行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_bastion_file_transfer_without_command_is_detected`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_bastion_file_transfer_without_command_is_detected`。
- P0 回归通过：`tests/test_p0_security.py` 共 26 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`type=bastion operation=file_upload file_path=/tmp/db.sql` 且无 `command` 字段时不会生成事件，也不会触发 `P0-BASTION-001`。
- 已新增无命令字段的堡垒机文件传输识别，输出 `堡垒机文件传输` 事件，MITRE `T1105`，标签 `bastion-command/file-transfer/bastion`。
- 已新增回归测试，覆盖事件字段、文件路径保留和既有 `P0-BASTION-001` 告警聚合。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Proxy Request Body Bytes

### 本轮目标
- 修复 proxy/SWG 日志中 `request_body_bytes` / `req_body_bytes` 达到阈值时不会触发 P0 数据外传的问题。
- 保持 `body_bytes_sent` / `response_body_bytes` 这类响应体字段不作为外发字节，避免大下载或大响应误报。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只在 proxy/SWG P0 adapter 的 request-body 上传字节别名中扩展，不把该语义泛化到 firewall/NAT。
- 不改变 P0 外传阈值、detector 聚合、correlation 语义或 output 格式。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_proxy_request_body_bytes_do_not_count_response_body_bytes`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_proxy_request_body_bytes_do_not_count_response_body_bytes`。
- P0 回归通过：`tests/test_p0_security.py` 共 25 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=proxy request_body_bytes=209715200` 和 `req_body_bytes=209715200` 不生成 P0 外传事件，也不会触发 `P0-EXFIL-001`。
- 已将 proxy/SWG 的 request-body 字节别名纳入外发归一化，覆盖 `request_body_bytes/requestbodybytes/req_body_bytes/reqbodybytes`。
- 已新增回归测试，覆盖 request-body 上传触发、`body_bytes_sent/response_body_bytes` 不触发。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Outbound Originator Bytes

### 本轮目标
- 修复 Zeek/代理/防火墙类日志中 `direction=outbound/egress` 且 `orig_bytes` 达到阈值时不会触发 P0 数据外传的问题。
- 保持 `resp_bytes` / responder bytes 不作为外发字节，避免大下载或响应体误报。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只在明确外发方向时读取 `orig_bytes/origin_bytes/originator_bytes`，无方向字段时不把 originator bytes 当成外发。
- 不改变 P0 外传阈值、detector 聚合、correlation 语义或 output 格式。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_outbound_originator_bytes_do_not_count_response_bytes`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_outbound_originator_bytes_do_not_count_response_bytes`。
- P0 回归通过：`tests/test_p0_security.py` 共 24 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`direction=outbound orig_bytes=209715200` 的 proxy 记录和 `direction=egress orig_bytes=209715200` 的 firewall 记录不会生成 P0 外传事件，也不会触发 `P0-EXFIL-001`。
- 已新增明确外发方向下的 originator bytes 归一化，覆盖 `orig_bytes/origin_bytes/originator_bytes`。
- 已新增回归测试，覆盖 outbound/egress `orig_bytes` 触发、outbound `resp_bytes` 不触发、ingress `orig_bytes` 不触发。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Inbound Direction Veto For Byte Aliases

### 本轮目标
- 修复 P0 proxy/firewall 中明确外发字节别名绕过 `direction=inbound/ingress` 的问题，避免入站大流量被误报为数据外传。
- 保留无方向字段时对 `bytes_sent/upload_bytes/request_bytes` 等明确外发别名的兼容。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只在 P0 parser 的字节归一化里增加清晰入站方向 veto，不改变 detector、correlation、output、remote 的职责边界。
- 只拦截 `inbound/ingress/download/server-to-client/s2c/入站/下行/下载/流入` 等明确入站语义；无方向字段的明确外发别名仍保持原行为。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_inbound_direction_vetoes_explicit_bytes_out_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_inbound_direction_vetoes_explicit_bytes_out_aliases`。
- P0 回归通过：`tests/test_p0_security.py` 共 23 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`direction=inbound bytes_sent=209715200` 的 proxy 记录和 `direction=ingress upload_bytes=209715200` 的 firewall 记录会被误报为“代理大流量外发/防火墙大流量外联”，并触发 `P0-EXFIL-001`。
- 已新增 `_is_inbound_direction()`，让明确入站方向优先阻断外发字节归一化。
- 已新增回归测试，覆盖 proxy/firewall 中明确入站方向与显式字节别名冲突时不生成 P0 外传事件。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Proxy Client-To-Server Bytes Aliases

### 本轮目标
- 修复 W3C/代理类 CSV 日志中 `cs-bytes` / client-to-server 上传字节不会触发 P0 数据外传的问题。
- 同时确认 `sc-bytes` / server-to-client 响应字节不会被误报为外发流量。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只在 proxy/SWG P0 adapter 中扩展 client-to-server 字节别名，不把 `cs-bytes` 泛化到 firewall/NAT。
- 不改变 P0 外传阈值、detector 聚合、correlation 语义或 output 格式。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_proxy_csv_accepts_client_to_server_bytes_only`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_proxy_csv_accepts_client_to_server_bytes_only`。
- P0 回归通过：`tests/test_p0_security.py` 共 22 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`log_type=proxy cs_bytes=209715200` 不生成 P0 事件，也不会触发 `P0-EXFIL-001`。
- 已将 proxy/SWG 的 client-to-server 字节别名纳入外发归一化，覆盖 `cs-bytes/cs_bytes`、`client_to_server_bytes`、`c2s_bytes` 等常见写法。
- 已保留 `sc-bytes` 为响应/下载方向，不作为外发字节别名。
- 已新增 CSV 回归测试，覆盖大 `cs-bytes` 触发和大 `sc-bytes` 不触发。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Direction-Aware Generic Bytes

### 本轮目标
- 修复 P0 proxy/firewall 对泛用 `bytes` 字段缺少方向判断的问题，避免 `direction=inbound/ingress` 的大下载或入站流量被误报为数据外传。
- 保留明确外发字段和明确 `direction=outbound/egress` 的泛用 `bytes` 检测能力。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只改变 P0 parser 对字节方向的解释，不改变 detector 聚合、不改变外传阈值、不改变 parser/detector/correlation/output/remote 的职责边界。
- `response_bytes` 不再作为外发字节别名；外发以 `request_bytes/upload_bytes/sent_bytes/out_bytes/tx_bytes/bytes_sent` 等明确别名，或带 outbound/egress/upload 方向的泛用 `bytes` 为准。
- 不引入网络行为，不读取额外文件，不改变 remote 只读白名单。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_generic_bytes_respects_traffic_direction`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_generic_bytes_respects_traffic_direction`。
- P0 回归通过：`tests/test_p0_security.py` 共 21 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：`direction=inbound bytes=209715200` 的 proxy/firewall 记录会被误报为“代理大流量外发/防火墙大流量外联”，并触发 `P0-EXFIL-001`；同时 `details["bytes_out"]` 仍为 `0`。
- 已将泛用 `bytes` 改为只有明确 outbound/egress/upload 方向时才参与外发判断。
- 已把 `details["bytes_out"]` 和触发逻辑统一到方向感知 `_bytes_out()`。
- 已新增回归测试，覆盖 outbound/egress 泛用 `bytes` 仍触发、inbound/ingress 泛用 `bytes` 不触发、单独 `response_bytes` 不触发。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - P0 Bytes Out Alias Compatibility

### 本轮目标
- 修复 P0 proxy/firewall 大流量外发检测只识别少数字节字段的问题，兼容真实设备常见的 `request_bytes`、`bytes_sent`、`tx_bytes`、`bytes_uploaded` 等外发导出字段。

### 涉及模块
- `bla/parsers/p0_security.py`
- `tests/test_p0_security.py`

### 风险边界
- 只扩展 P0 parser 对“外发字节数”字段名的归一化，不改变阈值、不改变 detector 聚合逻辑、不改变事件/告警职责边界。
- 不引入联网行为，不读取额外文件，不改变 remote 只读白名单。
- 对 `details["bytes_out"]` 使用同一套归一化，避免 parser 触发逻辑和输出字段不一致。

### 验证命令
- `python3 -m pytest -q tests/test_p0_security.py::P0SecurityRegressionTests::test_p0_proxy_and_firewall_accept_common_bytes_out_aliases`
- `python3 -m pytest -q tests/test_p0_security.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_p0_proxy_and_firewall_accept_common_bytes_out_aliases`。
- P0 回归通过：`tests/test_p0_security.py` 共 20 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现现状：`request_bytes=209715200` 的 proxy 记录和 `bytes_sent=209715200` 的 firewall 记录不会生成任何 P0 事件，也不会触发 `P0-EXFIL-001`。
- 已新增 `_bytes_out()` 字段归一化，覆盖 `bytes_out/bytesout/sent_bytes/sentbytes/bytes_sent/bytessent/upload_bytes/uploadbytes/bytes_uploaded/bytesuploaded/out_bytes/outbytes/tx_bytes/txbytes/request_bytes/requestbytes`。
- 已将 proxy/firewall 大流量外发判断和 `details["bytes_out"]` 切到同一套归一化。
- 已新增回归测试，覆盖 proxy `request_bytes`、firewall `bytes_sent`，并断言触发 `P0-EXFIL-001`。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Shell History Data Exfiltration Detection

### 本轮目标
- 补齐 Shell History 中常见本地文件外传命令的解析和告警能力，覆盖 `scp/rsync` 上传、`curl --upload-file/-T/-F file=@`、`nc < file` 等场景。

### 涉及模块
- `bla/parsers/shell_history.py`
- `bla/detection/engine.py`
- `tests/test_parsers.py`
- `tests/test_detection.py`

### 风险边界
- Parser 只把命令历史归一为 `LogEvent`，不直接生成告警；Detector 通过 `DetectorRegistry` 新增独立 `data-exfiltration` detector，并使用 selector 预筛 `shell-exfiltration/data-exfiltration` 事件。
- 不改变 CLI、pipeline、correlation、output 和 remote 的职责边界。
- 不引入联网行为，不读取额外文件，不扩大 remote 命令白名单。
- 避免把远端下载到本地的 `scp analyst@host:/tmp/report ./report` 误判为外传。

### 验证命令
- `python3 -m pytest -q tests/test_parsers.py::ParserRegressionTests::test_shell_history_parser_detects_data_exfiltration_commands`
- `python3 -m pytest -q tests/test_detection.py::DetectionRegressionTests::test_shell_history_data_exfiltration_creates_alert_and_incident`
- `python3 -m pytest -q tests/test_parsers.py tests/test_detection.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_shell_history_parser_detects_data_exfiltration_commands`。
- 定点回归通过：`test_shell_history_data_exfiltration_creates_alert_and_incident`。
- Parser/Detector 相关回归通过：`tests/test_parsers.py tests/test_detection.py` 共 71 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现现状：`scp /var/backups/db.sql.gz attacker@...:/tmp/` 和 `nc host port < /etc/passwd` 不生成事件，`curl --upload-file ...` 被归为普通远程工具下载。
- 已新增 Shell History 外传命令识别，输出 `Shell 数据外传命令` 事件，MITRE `T1041`，标签 `shell-exfiltration/data-exfiltration`。
- 已新增 `EXFIL-001` 检测器，通过 registry 注册并使用 selector 预筛事件，生成数据外传告警、攻击链阶段和处置建议。
- 已新增 parser 和 detector 回归测试，覆盖正常外传命令、inbound `scp` 非外传样本和 Windows 本地盘符目标非外传样本。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Fatal Traceback Terminal Sanitization

### 本轮目标
- 修复顶层 fatal exception handler 中 `traceback.print_exc()` 绕过已清洗错误摘要的问题，避免异常消息里的 OSC/ANSI 控制字符和 token/password 等敏感片段进入终端。

### 涉及模块
- `bla/utils/helpers.py`
- `bla/cli/main.py`
- `bla_cli.py`
- `tests/test_release_hygiene.py`

### 风险边界
- 只改变未预期异常的终端 traceback 展示文本，不改变正常 CLI 参数、解析、检测、关联、报告写入或退出码语义。
- 保留 traceback 结构用于本地调试，但对整段 traceback 做控制字符清理和 secret 脱敏。
- 不引入网络行为，不改变 remote 只读白名单边界。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_fatal_traceback_redacts_terminal_output`
- `python3 -m pytest -q tests/test_release_hygiene.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_fatal_traceback_redacts_terminal_output`。
- Release hygiene 回归通过：`tests/test_release_hygiene.py` 共 12 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：兼容入口 `bla_cli.py` 的 fatal handler 会先打印已清洗摘要，然后通过原始 `traceback.print_exc()` 再次泄漏 ESC/OSC payload 和 `token=super-secret`。
- 已新增共享 `print_sanitized_traceback`，对格式化 traceback 统一执行 `sanitize_report_text` 后再写入 stderr。
- 已将 `bla_cli.py` 和 `python -m bla.cli.main` 的 fatal handler 切换为清洗后的 traceback 输出。
- 已新增回归测试，断言 fatal traceback 不包含 ESC、OSC payload 或原始 secret，并保留 `Traceback` 和 `token=<redacted>`。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Output Path Terminal Sanitization

### 本轮目标
- 修复报告产物写入提示中输出路径未统一清洗的问题，避免恶意文件名或目录名把 OSC/ANSI 控制字符、token/password 等敏感片段带入终端。

### 涉及模块
- `bla/output/bundle.py`
- `bla/output/html_report.py`
- `bla/output/json_report.py`
- `bla/output/csv_report.py`
- `bla/output/sarif_report.py`
- `bla/output/manifest.py`
- `tests/test_outputs.py`

### 风险边界
- 只改变终端提示里的显示文本，不改变真实输出路径、报告内容结构、解析/检测/关联语义。
- 不引入网络访问，不改变 HTML 离线渲染方式。
- 不触碰 remote 任意命令边界。

### 验证命令
- `python3 -m pytest -q tests/test_outputs.py::OutputRegressionTests::test_report_bundle_sanitizes_terminal_output_paths`
- `python3 -m pytest -q tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_report_bundle_sanitizes_terminal_output_paths`。
- 输出模块回归通过：`tests/test_outputs.py` 全部通过。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：恶意输出目录名包含 OSC52 控制序列和 `token=super-secret` 时，报告 bundle 成功提示会把控制字符和 secret 原样写到终端。
- 已修复 bundle、HTML、JSON、CSV、SARIF、manifest 的报告保存提示，统一对输出路径调用 `sanitize_report_text`。
- 已新增 `test_report_bundle_sanitizes_terminal_output_paths`，覆盖恶意输出目录下的完整报告 bundle 生成，并断言终端输出不包含 OSC/BEL 控制字符和原始 secret。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 未提交改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - CLI Failure Path Secret Redaction

### 本轮目标
- 修复 CLI/Remote 报告写入失败和异常提示中只去除控制字符、不脱敏 secret 的问题。
- 让终端清洗同时覆盖 Python 异常字符串中被 repr 成 `\x1b...\x07` 的转义控制序列，避免 OSC payload 以文本形式留在 stderr。

### 涉及模块
- `bla/utils/helpers.py`
- `bla/cli/main.py`
- `bla_cli.py`
- `bla/remote/ssh_workspace.py`
- `tests/test_release_hygiene.py`
- `tests/test_remote_workspace.py`

### 风险边界
- 只改变终端/错误展示文本，不改变真实文件路径、不改变 parser/detector/correlation 语义。
- 不引入网络行为，不改变 remote 采集命令白名单。
- 不改变 JSON/CSV/HTML/SARIF/manifest 文件结构。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_cli_report_write_failure_redacts_terminal_output`
- `python3 -m pytest -q tests/test_remote_workspace.py::RemoteWorkspaceRegressionTests::test_remote_workspace_report_write_error_redacts_terminal_output`
- `python3 -m pytest -q tests/test_release_hygiene.py tests/test_remote_workspace.py tests/test_outputs.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：本地 CLI 报告写入失败不再泄漏 OSC payload 或 `super-secret`。
- 定点回归通过：Remote Workspace 报告写入失败不再泄漏 OSC payload 或 `super-secret`。
- 受影响测试组通过：`tests/test_release_hygiene.py tests/test_remote_workspace.py tests/test_outputs.py` 共 50 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：当 `--json` 指向名为 `\x1b]52;c;SGVsbG8=\x07token=super-secret` 的目录时，CLI 报告写入失败会在 stderr 中泄漏 `super-secret` 和 OSC payload 文本。
- 已将 CLI 主入口、兼容 shim、Remote Workspace 的异常展示从仅去控制字符改为 `sanitize_report_text`。
- 已增强 `strip_terminal_control`，让 Python 异常中以文本形式出现的 `\x1b...\x07`、`\x1b[...` 等转义控制序列也会被清理。
- 已新增本地 CLI 和 Remote Workspace 两条失败分支回归测试。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Remote Workspace pwd Sanitization

### 本轮目标
- 修复 Remote Workspace `pwd` 命令直接打印 `self.cwd` 的问题，避免初始 cwd 或远端 `pwd -P` 返回值中的控制字符和 secret 进入终端。

### 涉及模块
- `bla/remote/ssh_workspace.py`
- `tests/test_remote_workspace.py`

### 风险边界
- 只改变 `pwd` 命令的展示文本，不改变 `self.cwd` 内部值、不改变远端命令构造和目录解析。
- 不扩大 remote 命令白名单，不新增远端写入或联网行为。
- 不改变 parser/detector/correlation/output 文件结构。

### 验证命令
- `python3 -m pytest -q tests/test_remote_workspace.py::RemoteWorkspaceRegressionTests::test_remote_workspace_pwd_redacts_terminal_output`
- `python3 -m pytest -q tests/test_remote_workspace.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_remote_workspace_pwd_redacts_terminal_output`。
- Remote 工作区回归通过：`tests/test_remote_workspace.py` 共 16 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：Remote Workspace 的 `pwd` 在 `cwd=/var/log/\x1b]52;c;SGVsbG8=\x07-token=super-secret` 时会原样输出 ESC/OSC payload 和 `super-secret`。
- 已修复 Remote Workspace `pwd` 输出，展示当前目录时统一走 `_display_text`。
- 已新增回归测试，断言 `pwd` 输出不包含 ESC、OSC payload 或原始 secret，并保留 `token=<redacted>` 语义。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Remote Workspace ls Argument Sanitization

### 本轮目标
- 修复 Remote Workspace `ls` 对不支持参数报错时直接打印用户输入参数的问题，避免 remote 交互工作台错误出口泄漏控制字符和 secret。

### 涉及模块
- `bla/remote/ssh_workspace.py`
- `tests/test_remote_workspace.py`

### 风险边界
- 只改变 `ls` 参数校验失败的终端展示，不改变允许的 remote 命令集合和远端只读边界。
- 不改变 `ls` 正常路径解析、白名单命令构造、fetch/tail/grep 分析流程。
- 不引入网络行为，不改变 parser/detector/correlation/output 文件结构。

### 验证命令
- `python3 -m pytest -q tests/test_remote_workspace.py::RemoteWorkspaceRegressionTests::test_remote_workspace_ls_argument_error_redacts_terminal_output`
- `python3 -m pytest -q tests/test_remote_workspace.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_remote_workspace_ls_argument_error_redacts_terminal_output`。
- Remote 工作区回归通过：`tests/test_remote_workspace.py` 共 15 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：Remote Workspace 执行 `ls --\x1b]52;c;SGVsbG8=\x07-token=super-secret` 时，stderr 会原样输出 ESC/OSC payload 和 `super-secret`。
- 已修复 Remote Workspace `ls` 不支持参数错误展示，参数值统一走 `_display_text`。
- 已新增回归测试，断言错误输出不包含 ESC、OSC payload 或原始 secret，并保留 `token=<redacted>` 语义。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - argparse Failure Path Terminal Sanitization

### 本轮目标
- 修复 argparse 在 invalid choice / unrecognized arguments 等参数解析失败路径中直接打印用户输入参数的问题，避免还没进入业务逻辑时就把恶意控制序列和 secret 打到终端。

### 涉及模块
- `bla/utils/helpers.py`
- `bla/cli/main.py`
- `bla/remote/ssh_workspace.py`
- `tests/test_release_hygiene.py`
- `tests/test_remote_workspace.py`

### 风险边界
- 只改变 argparse 错误消息的终端展示，不改变参数定义、默认值、choices、退出码或正常 `--help` 输出语义。
- 不改变 parser/detector/correlation/output 文件结构。
- Remote workspace 仍只解析受限 `bla` 采集参数，不扩大远端命令白名单，不引入远端写入或联网行为。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_argparse_errors_redact_terminal_output`
- `python3 -m pytest -q tests/test_remote_workspace.py::RemoteWorkspaceRegressionTests::test_remote_workspace_argparse_error_redacts_terminal_output`
- `python3 -m pytest -q tests/test_release_hygiene.py tests/test_remote_workspace.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：主 CLI 和 `remote-log` 子命令的 argparse invalid choice 错误不再泄漏 OSC payload 或原始 secret。
- 定点回归通过：Remote Workspace 内部 `bla` 参数解析失败不再泄漏 OSC payload 或原始 secret。
- 受影响测试组通过：`tests/test_release_hygiene.py tests/test_remote_workspace.py` 共 25 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：主 CLI `--exit-on` invalid choice 中包含 `\x1b]52;c;SGVsbG8=\x07-token=super-secret` 时，argparse 会在 stderr 中打印 `\x1b` 文本 payload 和原始 `super-secret`。
- 已新增 `SafeArgumentParser`，在 argparse `error()` 输出前统一调用 `sanitize_report_text`。
- 已将主 CLI、CLI 子命令和 Remote Workspace 内部 `bla` 参数解析切换到 `SafeArgumentParser`。
- 已新增主 CLI/子命令和 Remote Workspace 两条回归测试，覆盖 invalid choice 失败路径。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - explain Failure Path Terminal Sanitization

### 本轮目标
- 修复 `bla explain` 在报告读取失败、找不到目标 ID 时直接打印用户输入 `--report` 路径或 `id` 的问题，避免恶意路径/ID 向终端注入控制字符并泄漏 secret。

### 涉及模块
- `bla/cli/main.py`
- `tests/test_release_hygiene.py`

### 风险边界
- 只改变 `bla explain` 错误提示的终端展示，不改变 JSON 报告读取、alert/incident 匹配、text/markdown 正常输出语义。
- 不改变 parser、detector、correlation、output 文件结构。
- 不引入网络行为，不扩大 remote 能力。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_explain_failure_paths_redact_terminal_output`
- `python3 -m pytest -q tests/test_release_hygiene.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_explain_failure_paths_redact_terminal_output`。
- Release hygiene 回归通过：`tests/test_release_hygiene.py` 共 10 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：恶意 `--report` 路径和未命中 `id` 包含 `\x1b]52;c;SGVsbG8=\x07 token=super-secret` 时，`bla explain` 会把 ESC/OSC payload 和原始 secret 打到 stderr。
- 已修复 `bla explain` 的报告读取失败错误展示，`--report` 路径和异常文本统一走 `sanitize_report_text`。
- 已修复 `bla explain` 的未命中 ID 错误展示，目标 ID 统一走 `sanitize_report_text`。
- 已新增回归测试，同时覆盖报告不可读和报告可读但 ID 未命中两条失败路径。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - validate-rules Terminal Sanitization

### 本轮目标
- 修复 `validate-rules` 打印自定义规则 issue 时未清洗 `source` / `rule` / `message` 的问题，避免恶意规则目录或规则 ID 向终端注入控制字符并泄漏 secret。

### 涉及模块
- `bla/cli/main.py`
- `tests/test_release_hygiene.py`

### 风险边界
- 只改变 CLI 终端展示，不改变 `validate_web_attack_rules()` 返回的结构化校验结果。
- 不改变规则加载、规则匹配、detector 注册或 Web 检测语义。
- 不引入网络行为，不影响 HTML/JSON/CSV/SARIF/manifest 文件结构。

### 验证命令
- `python3 -m pytest -q tests/test_release_hygiene.py::ReleaseHygieneRegressionTests::test_validate_rules_output_redacts_untrusted_rule_metadata`
- `python3 -m pytest -q tests/test_release_hygiene.py`
- `python3 bla_cli.py validate-rules --strict-metadata`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_validate_rules_output_redacts_untrusted_rule_metadata`。
- Release hygiene 回归通过：`tests/test_release_hygiene.py` 共 9 条。
- 规则校验通过：`python3 bla_cli.py validate-rules --strict-metadata`。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：当 `--rules` 指向名为 `\x1b]52;c;SGVsbG8=\x07token=super-secret` 的目录时，`validate-rules --strict-metadata` 会在 stdout 中打印 ESC/OSC payload 和原始 secret。
- 已修复 `_cmd_validate_rules` 的 issue 输出，`source`、`rule`、`message` 统一走 `sanitize_report_text` 后再打印。
- 已新增回归测试，覆盖恶意规则目录名、缺失规则元数据、ReDoS warning 的混合失败路径，并断言 stdout 不含 ESC、OSC payload 或原始 secret。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。

## 2026-05-29 - Remote Audit JSON Local Name Sanitization

### 本轮目标
- 修复 remote `--audit-json` 中 `local_name` 字段可能保留远程文件名里的 OSC payload 和 secret 的问题。
- 保持 remote 采集仍然只读、限量、可审计，不改变实际临时文件路径和采集命令。

### 涉及模块
- `bla/remote/ssh_workspace.py`
- `tests/test_remote_workspace.py`

### 风险边界
- 只清洗审计/manifest 展示字段，不改变远端读取命令、grep/tail 逻辑、拉取文件内容和检测结果。
- 不引入网络行为，不扩大 remote 命令白名单。
- 不改变主报告 JSON/CSV/HTML/SARIF 结构。

### 验证命令
- `python3 -m pytest -q tests/test_remote_workspace.py::RemoteWorkspaceRegressionTests::test_remote_workspace_audit_json_sanitizes_local_name`
- `python3 -m pytest -q tests/test_remote_workspace.py`
- `python3 -m compileall -q bla bla_cli.py setup.py tests`
- `python3 -m pytest -q`
- `python3 -m unittest discover -s tests -v`
- `python3 scripts/release_check.py`

### 验证结果
- 定点回归通过：`test_remote_workspace_audit_json_sanitizes_local_name`。
- Remote 工作区回归通过：`tests/test_remote_workspace.py` 共 13 条。
- 发布级验证通过：`scripts/release_check.py` 通过，并覆盖 compileall、pytest、unittest、`validate-rules --strict-metadata`、ssh/remote-log help、1 MB benchmark、1 MB memory benchmark 和样例报告 smoke。

### 修改结果
- 已复现问题：恶意远程路径 `/var/log/\x1b]52;c;SGVsbG8=\x07token=super-secret.log` 经过 `--audit-json` 后，`collection[0].local_name` 中仍包含原始 secret 和 OSC payload。
- 已修复 remote input manifest 和 collection audit record 的 `local_name` 展示字段，统一走 `_display_text`。
- 已在写出 `--audit-json` 前增加递归清洗兜底，避免后续新增审计字段绕过清洗。
- 已新增回归测试，同时断言 audit JSON 和 manifest 的 remote collection 区域不包含 ESC、OSC payload 或原始 secret。

### 剩余问题
- 本轮未发现 P0/P1 已知问题。
- 当前工作树仍包含本轮之前已经存在的 CLI/JSON/release hardening 改动和 `soft-copyright-materials/` 未跟踪目录；本轮未回退或清理这些现场状态。
