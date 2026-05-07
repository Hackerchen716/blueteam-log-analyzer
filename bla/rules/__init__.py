"""外置检测规则支持。"""

from .loader import (
    WebAttackRule,
    get_web_attack_rules,
    reset_rule_cache,
    set_rule_dirs,
)

__all__ = [
    "WebAttackRule",
    "get_web_attack_rules",
    "reset_rule_cache",
    "set_rule_dirs",
]
