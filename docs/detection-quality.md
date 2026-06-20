# 检测质量评测（Detection Quality）

BLA 的检测质量不是"靠断言精挑的样例就算数"，而是**可度量、可回归、可用你自己的真实日志验证**的。本文档说明评测方法、当前结果，以及如何在你自己的数据上跑出 precision/recall。

## 为什么要度量

基于正则/签名匹配日志文本的检测，天然有误报风险。仅用"挑几个能过的样例做断言"会陷入"自己出题自己满分"。BLA 用一份**带标注的语料**（真实攻击 + *对抗性良性*：像攻击但实为正常的流量）来**测量** precision / recall / 误报率，并把结果设为回归门禁，防止质量悄悄退化。

## 方法

- 语料：[`tests/fixtures/detection_quality/cases.jsonl`](../tests/fixtures/detection_quality/cases.jsonl)，每行一个标注样本。
  - 真阳：各类 Web 攻击与 HVV 高频漏洞（SQLi/XSS/RCE/路径穿越/LFI/RFI/Webshell/Shiro/Fastjson/Struts2/ThinkPHP/Weblogic/Spring/反序列化/XXE/SSRF/未授权/OA/扫描器），含编码、内联注释、双编码等绕过变体。
  - **对抗性良性**：`?id=1`、含 `select/union/exec` 的业务词、`/wp-content` 图片、acme-challenge、合法 `curl/wget/python-requests` 客户端、携带外部 https 链接的 OAuth 回调/分享/图片代理、login POST 等——这些"看着像攻击"的正常流量决定了误报率是否可信。
  - 跨解析器：Linux SSH 爆破/正常、P0 VPN 爆破/正常等非 Web 场景（`content` + `parser`）。
- 信号：用 `run_detection` 产出的**真实告警**判定是否命中，等同用户实际所见，覆盖 Web 之外的爆破/横向/持久化等全部检测器。
- 评测器：[`scripts/eval_detection.py`](../scripts/eval_detection.py) 输出按类与总体的 TP/FP/FN、precision/recall/误报率矩阵，支持阈值退出码，已接入 `release_check.py` 与回归测试。

## 当前结果

77 个样本（38 真阳 + 39 对抗性良性）：**precision = 1.00，recall = 1.00，误报率 = 0.00**。

评测过程中**发现并修复的真实误报**（透明披露，均由对抗性良性样本暴露）：

| 误报 | 根因 | 修复 |
|------|------|------|
| 合法 `curl/wget/python-requests` 被当扫描器 | scanner 规则匹配通用客户端 UA | 仅保留专用攻击/扫描工具 UA |
| `/api/exec-report` 被当命令执行 | `\bexec\b` 命中路径里的单词 | 收紧为 `\bexec\s*\(`（仅 exec 调用） |
| `category=select-best-sellers` 被当 SQLi | `check_str` 重复拼接致 `select…select` 自匹配 | 去重（request 已含 path，decoded_path 仅在编码不同时追加） |
| `?url=https://...`（OAuth 回调/分享/图片代理）被当 SSRF | SSRF 规则匹配任意外部 URL | 仅危险协议(gopher/dict/file)或内网/回环/云元数据目标才告警 |

## 运行评测

```bash
# 跑内置语料
python3 scripts/eval_detection.py

# 带阈值门禁（CI/release 用）
python3 scripts/eval_detection.py --min-recall 0.95 --min-precision 0.95 --max-fp-rate 0.07
```

回归门禁见 [`tests/test_detection_quality.py`](../tests/test_detection_quality.py)，随 `pytest` 在 CI 执行。

## 用你自己的真实日志验证（推荐）

合成语料是真实世界的*近似*，不是 ground truth。要在你的真实 HVV/生产日志上得到 precision/recall，写一份**标注清单**指向真实日志文件即可：

清单格式（JSONL，每行一个对象，路径相对清单所在目录）：

```json
{"name": "edge-access-2024-03", "file": "logs/access-2024-03.log", "expect_alert": true,  "category": "web-attack"}
{"name": "internal-portal-normal", "file": "logs/portal-normal.log", "expect_alert": false, "category": "benign"}
```

- `file`：真实日志文件（Web access / Linux auth / Windows XML/JSON / P0 等，BLA 自动识别；也可用 `parser` 显式指定）。
- `expect_alert`：该文件是否应当产生告警（含已知攻击→`true`；确认干净→`false`）。

运行：

```bash
# 在内置语料之外，追加你的真实清单一起评测
python3 scripts/eval_detection.py --manifest /path/to/your-manifest.jsonl

# 或仅评测你自己的清单
python3 scripts/eval_detection.py --cases /path/to/your-manifest.jsonl
```

可参考可运行的示例：[`tests/fixtures/detection_quality/manifest.example.jsonl`](../tests/fixtures/detection_quality/manifest.example.jsonl)。

## 局限与诚实声明

- 内置 77 条语料是**强代理而非真值**；最有说服力的验证来自你用上面 manifest 跑自己的真实日志。
- 公开数据集（如 EVTX-ATTACK-SAMPLES、OTRF Security-Datasets、真实 access log 归档）可在本地渲染/落盘后，用同一 manifest 机制纳入评测。
- 文件级标注衡量的是"该文件是否应当告警"（适合度量误报与漏报覆盖），不替代逐事件的精细标注。
