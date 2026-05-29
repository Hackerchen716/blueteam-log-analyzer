"""集中管理 BLA 的检测阈值与参数。

所有"魔法数字"都集中在这里，方便：
1. 不同部署环境（公网跳板机 vs 内网监控）按需调整阈值；
2. 测试时直接 monkeypatch 这些常量；
3. 后续接入 ``--config thresholds.json`` 让用户从外部覆盖。

使用方式：

    from bla.config import THRESHOLDS
    if n >= THRESHOLDS.brute_force_critical: ...

新增配置项时请保持名字和注释自描述。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields, replace
from typing import Any, Dict


@dataclass(frozen=True)
class Thresholds:
    # ── 暴力破解（Linux Auth + Windows 4625）─────────────────────
    brute_force_min: int = 5      # 触发告警的最小失败次数
    brute_force_high: int = 20    # 升级到 HIGH 的失败次数
    brute_force_critical: int = 50  # 升级到 CRITICAL 的失败次数
    brute_force_window_minutes: int = 15

    # ── 密码喷洒 ────────────────────────────────────────────────
    spray_min_unique_users: int = 5
    spray_max_avg_per_user: float = 3.0
    spray_window_minutes: int = 15
    success_after_failure_window_minutes: int = 60

    # ── Web 流量异常（基于分钟桶）────────────────────────────────
    ddos_peak_per_minute: int = 300   # 单分钟峰值（约 5 req/s）
    ddos_min_total: int = 500         # 同时要求总量足够大，避免短时抖动
    scanning_peak_per_minute: int = 30
    scanning_min_total: int = 100

    # ── 侦察 / 敏感探测 ─────────────────────────────────────────
    recon_min_events: int = 10        # 触发"敏感文件探测"告警的最小次数
    scanner_min_events: int = 5       # 触发"扫描器"告警的最小次数

    # ── 权限提升 ───────────────────────────────────────────────
    sudo_denied_min: int = 3

    # ── 解析器限制 ─────────────────────────────────────────────
    generic_parse_line_limit: int = 10_000

    # ── 报告 ────────────────────────────────────────────────────
    timeline_max_items: int = 500
    cli_max_alerts_default: int = 50


# 单例：默认值。CLI / 测试可通过 ``override`` 临时替换部分字段。
DEFAULT_THRESHOLDS = Thresholds()
THRESHOLDS = DEFAULT_THRESHOLDS


def load_thresholds(path: str, base: Thresholds = DEFAULT_THRESHOLDS) -> Thresholds:
    """从 JSON 文件加载阈值，未指定的字段保留默认值。"""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("thresholds 文件必须是 JSON 对象")
    return _merge(base, raw)


def load_thresholds_from_env(base: Thresholds = DEFAULT_THRESHOLDS, validate: bool = True) -> Thresholds:
    """读取 ``BLA_THRESHOLD_*`` 环境变量覆盖默认值。

    例：``BLA_THRESHOLD_BRUTE_FORCE_HIGH=10`` 把 brute_force_high 改成 10。
    """
    overrides: Dict[str, Any] = {}
    field_names = {f.name for f in fields(Thresholds)}
    prefix = "BLA_THRESHOLD_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        attr = key[len(prefix):].lower()
        if attr in field_names:
            overrides[attr] = value
    return _merge(base, overrides, validate=validate)


def _merge(base: Thresholds, overrides: Dict[str, Any], validate: bool = True) -> Thresholds:
    """把字符串/数字 overrides 合并到 base，自动按字段类型 cast。"""
    field_types = {f.name: f.type for f in fields(Thresholds)}
    cleaned: Dict[str, Any] = {}
    for key, val in overrides.items():
        if key not in field_types:
            raise ValueError(f"未知阈值字段: {key}")
        ftype = field_types[key]
        try:
            if ftype is int or ftype == "int":
                cleaned[key] = int(val)
            elif ftype is float or ftype == "float":
                cleaned[key] = float(val)
            else:
                cleaned[key] = val
        except (TypeError, ValueError) as e:
            raise ValueError(f"阈值字段 {key}={val!r} 无法转换为 {ftype}: {e}") from e
    merged = replace(base, **cleaned)
    return validate_thresholds(merged) if validate else merged


def validate_thresholds(thresholds: Thresholds) -> Thresholds:
    """校验阈值之间的业务关系，避免配置合法但检测语义异常。"""
    errors = []
    if thresholds.brute_force_min <= 0:
        errors.append("brute_force_min 必须大于 0")
    if thresholds.brute_force_high < thresholds.brute_force_min:
        errors.append("brute_force_high 必须大于等于 brute_force_min")
    if thresholds.brute_force_critical < thresholds.brute_force_high:
        errors.append("brute_force_critical 必须大于等于 brute_force_high")
    if thresholds.spray_min_unique_users <= 0:
        errors.append("spray_min_unique_users 必须大于 0")
    if thresholds.spray_max_avg_per_user <= 0:
        errors.append("spray_max_avg_per_user 必须大于 0")
    if thresholds.timeline_max_items <= 0:
        errors.append("timeline_max_items 必须大于 0")
    if thresholds.generic_parse_line_limit <= 0:
        errors.append("generic_parse_line_limit 必须大于 0")
    if errors:
        raise ValueError("阈值配置不合法: " + "; ".join(errors))
    return thresholds


def set_thresholds(new_thresholds: Thresholds) -> None:
    """运行时替换全局阈值（测试与 CLI 用）。"""
    global THRESHOLDS
    THRESHOLDS = validate_thresholds(new_thresholds)
