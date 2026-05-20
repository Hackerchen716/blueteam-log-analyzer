"""轻量级外置规则加载器。

BLA 保持零依赖：如果环境里安装了 PyYAML，就用 ``yaml.safe_load``；否则使用
一个只覆盖本项目规则格式的极小 YAML 子集解析器。这样普通用户不用额外安装库，
安全研究员也可以直接编辑 ``rules/*.yaml`` 扩展 Web 检测。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

from ..models import ThreatLevel


@dataclass(frozen=True)
class WebAttackRule:
    rule_id: str
    pattern: Pattern[str]
    level: ThreatLevel
    category: str
    name: str
    mitre: str
    tags: List[str]
    confidence: str = "medium"
    source_types: Optional[List[str]] = None
    evidence_fields: Optional[List[str]] = None
    false_positive_hints: Optional[List[str]] = None
    remediation: str = ""


_RULE_DIRS: Tuple[str, ...] = ()
_NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?[^)]*(?:\.\*|\.\+|\\[wWsSdD]\+|\[[^\]]+\]\+|[A-Za-z0-9]\+)[^)]*\)[+*{]"
)
_REPEATED_DOTSTAR_RE = re.compile(r"\.\*.*\.\*")


def set_rule_dirs(paths: Iterable[str]) -> None:
    """设置自定义规则目录，并清空缓存。"""
    global _RULE_DIRS
    normalized = []
    for path in paths:
        if not path:
            continue
        abspath = os.path.abspath(path)
        if not os.path.isdir(abspath):
            raise ValueError(f"规则目录不存在: {path}")
        normalized.append(abspath)
    validation = validate_web_attack_rules(normalized)
    if validation["errors"]:
        messages = "; ".join(
            f"{item['source']}::{item['rule']}: {item['message']}"
            for item in validation["issues"]
            if item["severity"] == "error"
        )
        raise ValueError(f"规则校验失败: {messages}")
    _RULE_DIRS = tuple(normalized)
    reset_rule_cache()


def reset_rule_cache() -> None:
    _load_web_attack_rules_cached.cache_clear()


def get_web_attack_rules() -> List[WebAttackRule]:
    """读取内置规则和用户自定义规则。用户规则优先生效。"""
    return list(_load_web_attack_rules_cached(_RULE_DIRS))


def validate_web_attack_rules(rule_dirs: Iterable[str] = ()) -> Dict[str, Any]:
    """Validate built-in and custom web rule metadata without running detection."""
    normalized_dirs = tuple(os.path.abspath(path) for path in rule_dirs if path)
    raw_rules: List[Tuple[str, Dict[str, Any]]] = []
    for directory in normalized_dirs:
        if not os.path.isdir(directory):
            raise ValueError(f"规则目录不存在: {directory}")
        for fname in sorted(os.listdir(directory)):
            if not fname.lower().endswith((".yaml", ".yml")):
                continue
            path = os.path.join(directory, fname)
            with open(path, "r", encoding="utf-8") as f:
                raw_rules.extend((path, item) for item in _extract_web_attacks(_load_yamlish(f.read())))
    raw_rules.extend(("<builtin:web_attacks.yaml>", item) for item in _load_builtin_rules())

    issues: List[Dict[str, str]] = []
    compiled = 0
    required = ("id", "name", "mitre", "tags", "patterns")
    metadata = ("source_types", "evidence_fields", "false_positive_hints", "remediation")
    for source, raw in raw_rules:
        rule_name = str(raw.get("id") or raw.get("rule_id") or raw.get("name") or "<unnamed>")
        for field in required:
            if field not in raw:
                issues.append({"severity": "error", "source": source, "rule": rule_name, "message": f"缺少必填字段: {field}"})
        if "severity" not in raw and "level" not in raw:
            issues.append({"severity": "error", "source": source, "rule": rule_name, "message": "缺少必填字段: severity 或 level"})
        for field in metadata:
            if field not in raw:
                issues.append({"severity": "warning", "source": source, "rule": rule_name, "message": f"缺少规则元数据: {field}"})
        for message in _lint_regex_patterns(raw.get("patterns") or []):
            issues.append({"severity": "warning", "source": source, "rule": rule_name, "message": message})
        try:
            compiled += len(_compile_web_rule(raw))
        except Exception as exc:
            issues.append({"severity": "error", "source": source, "rule": rule_name, "message": f"规则无法编译: {exc}"})
    return {
        "raw_rules": len(raw_rules),
        "compiled_patterns": compiled,
        "errors": sum(1 for item in issues if item["severity"] == "error"),
        "warnings": sum(1 for item in issues if item["severity"] == "warning"),
        "issues": issues,
    }


@lru_cache(maxsize=8)
def _load_web_attack_rules_cached(rule_dirs: Tuple[str, ...]) -> Tuple[WebAttackRule, ...]:
    raw_rules: List[Dict[str, Any]] = []

    # 用户规则优先，便于用更精确的规则覆盖内置规则命中顺序。
    for directory in rule_dirs:
        raw_rules.extend(_load_rules_from_dir(directory))

    raw_rules.extend(_load_builtin_rules())
    compiled: List[WebAttackRule] = []
    for raw in raw_rules:
        try:
            compiled.extend(_compile_web_rule(raw))
        except Exception:
            # 外置规则单条失败不应导致整份日志无法分析。后续可以在 verbose
            # 模式下暴露具体错误；当前先保持 CLI 行为稳定。
            continue
    return tuple(compiled)


def _load_builtin_rules() -> List[Dict[str, Any]]:
    try:
        text = resources.files(__package__).joinpath("web_attacks.yaml").read_text(encoding="utf-8")
    except Exception:
        return []
    return _extract_web_attacks(_load_yamlish(text))


def _load_rules_from_dir(directory: str) -> List[Dict[str, Any]]:
    if not os.path.isdir(directory):
        raise ValueError(f"规则目录不存在: {directory}")

    loaded: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(directory)):
        if not fname.lower().endswith((".yaml", ".yml")):
            continue
        path = os.path.join(directory, fname)
        with open(path, "r", encoding="utf-8") as f:
            loaded.extend(_extract_web_attacks(_load_yamlish(f.read())))
    return loaded


def _extract_web_attacks(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        value = data.get("web_attacks", [])
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _compile_web_rule(raw: Dict[str, Any]) -> List[WebAttackRule]:
    patterns = raw.get("patterns") or []
    if isinstance(patterns, str):
        patterns = [patterns]
    if not patterns:
        return []

    rule_id = str(raw.get("id") or raw.get("rule_id") or raw.get("name") or "WEB-CUSTOM")
    name = str(raw.get("name") or rule_id)
    category = str(raw.get("category") or "Web攻击")
    mitre = str(raw.get("mitre") or raw.get("mitre_attack") or "T1190")
    tags = raw.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    level_name = str(raw.get("severity") or raw.get("level") or "medium").lower()
    level = {
        "critical": ThreatLevel.CRITICAL,
        "high": ThreatLevel.HIGH,
        "medium": ThreatLevel.MEDIUM,
        "low": ThreatLevel.LOW,
        "info": ThreatLevel.INFO,
    }.get(level_name, ThreatLevel.MEDIUM)

    confidence = str(raw.get("confidence") or "medium").lower()
    source_types = _as_str_list(raw.get("source_types") or ["web", "waf", "application", "proxy"])
    evidence_fields = _as_str_list(raw.get("evidence_fields") or ["url", "uri", "path", "request", "user_agent"])
    false_positive_hints = _as_str_list(raw.get("false_positive_hints") or [])
    remediation = str(raw.get("remediation") or "")

    flags = re.IGNORECASE
    compiled = []
    for pattern_text in patterns:
        compiled.append(WebAttackRule(
            rule_id=rule_id,
            pattern=re.compile(str(pattern_text), flags),
            level=level,
            category=category,
            name=name,
            mitre=mitre,
            tags=list(dict.fromkeys([str(tag) for tag in tags])),
            confidence=confidence,
            source_types=source_types,
            evidence_fields=evidence_fields,
            false_positive_hints=false_positive_hints,
            remediation=remediation,
        ))
    return compiled


def _lint_regex_patterns(patterns: Any) -> List[str]:
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list):
        return []
    issues: List[str] = []
    for pattern in patterns:
        text = str(pattern)
        if len(text) > 800:
            issues.append("正则长度超过 800 字符，建议拆分为多条更小的规则")
        if _NESTED_QUANTIFIER_RE.search(text):
            issues.append(f"正则可能存在灾难性回溯风险: {text[:120]}")
        if _REPEATED_DOTSTAR_RE.search(text):
            issues.append(f"正则包含多个 .*，建议改成有边界的字段匹配: {text[:120]}")
    return issues


def _as_str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return []


def _load_yamlish(text: str) -> Any:
    try:
        import yaml  # type: ignore
    except Exception:
        return _parse_simple_yaml(text)
    return yaml.safe_load(text) or {}


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """解析 BLA 规则使用的 YAML 子集。

    支持：
    - 顶层 ``web_attacks:``
    - ``- id: ...`` 形式的对象列表
    - ``key: value``
    - ``patterns:`` / ``tags:`` 下的 ``- value`` 列表
    - ``tags: [a, b]`` 这类简单内联列表
    """
    result: Dict[str, Any] = {}
    current_root = ""
    current_item: Optional[Dict[str, Any]] = None
    current_list_key = ""

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0 and line.endswith(":"):
            current_root = line[:-1].strip()
            result.setdefault(current_root, [])
            current_item = None
            current_list_key = ""
            continue

        if line.startswith("- "):
            item_text = line[2:].strip()
            if indent <= 2:
                current_item = {}
                result.setdefault(current_root or "web_attacks", []).append(current_item)
                current_list_key = ""
                if item_text:
                    key, value = _split_key_value(item_text)
                    current_item[key] = _parse_scalar(value)
                continue
            if current_item is not None and current_list_key:
                current_item.setdefault(current_list_key, []).append(_parse_scalar(item_text))
                continue

        if current_item is not None and ":" in line:
            key, value = _split_key_value(line)
            if value == "":
                current_item[key] = []
                current_list_key = key
            else:
                current_item[key] = _parse_scalar(value)
                current_list_key = ""

    return result


def _split_key_value(text: str) -> Tuple[str, str]:
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
        inner = value[1:-1]
        return inner.replace("\\" + value[0], value[0])
    return value
