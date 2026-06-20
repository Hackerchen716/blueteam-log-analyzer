"""End-to-end attack-chain coverage gate.

用一份紧凑的统一多源样本（覆盖侦察→凭据→初始访问→执行→持久化→收集→C2→外传→清理）
固化多源解析 + 检测 + 攻击链还原的端到端能力。它永久守护两处真实数据暴露并修复的
回归点：
  1. 统一多源 JSONL 必须按 source 分流到各子解析器（含 shell_history 与 EDR
     technique 提取），不能被单一解析器认领、其余静默丢弃；
  2. 带头部 / 非 .bash_history 命名的 shell 记录里的 ``unset HISTFILE`` 等清理痕迹
     （T1070）必须被还原进攻击链。
"""
from _support import *  # noqa: F401,F403

from pathlib import Path

CHAIN_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "attack_chain" / "unified_chain.jsonl"

# 完整 kill chain 关键技术前缀（不含 lateral：紧凑样本里单条登录不足以触发跨主机关联，
# 真实多文件数据中由"爆破后成功登录"关联覆盖）。
REQUIRED_TECHNIQUE_PREFIXES = (
    "T1190",     # 初始访问 / Web 利用
    "T1110",     # 凭据攻击（爆破/喷洒）
    "T1059",     # 执行
    "T1053",     # 持久化（计划任务）
    "T1560",     # 收集（归档）
    "T1071",     # C2
    "T1041",     # 数据外传
    "T1070",     # 清理 / 反取证
)


class AttackChainCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = auto_parse(str(CHAIN_FIXTURE))
        cls.summary = run_detection(cls.result.events)
        cls.event_mitres = {str(e.mitre_attack or "") for e in cls.result.events}
        cls.chain_techniques = set()
        for stage in cls.summary.attack_chain:
            cls.chain_techniques.update(stage.techniques)

    def test_parsed_as_unified_multi_source(self):
        self.assertEqual(self.result.log_type, "Unified Multi-Source (JSONL)")
        self.assertGreaterEqual(self.result.stats.total, 12)

    def test_risk_is_critical(self):
        self.assertGreaterEqual(self.summary.risk_score, 80)
        self.assertTrue(self.summary.alerts)

    def test_kill_chain_stage_coverage(self):
        covered = self.event_mitres | self.chain_techniques
        missing = [
            prefix for prefix in REQUIRED_TECHNIQUE_PREFIXES
            if not any(tech.startswith(prefix) for tech in covered)
        ]
        self.assertEqual(missing, [], f"攻击链缺少阶段: {missing}; 已覆盖: {sorted(covered)}")

    def test_cleanup_and_edr_techniques_survive_unified_routing(self):
        # 守护两处真实数据回归：shell 清理(T1070) 与 EDR 提取的 C2/外传技术。
        self.assertTrue(any(t.startswith("T1070") for t in self.event_mitres), "shell 清理痕迹丢失")
        self.assertIn("T1071.001", self.event_mitres)
        self.assertIn("T1041", self.event_mitres)


if __name__ == "__main__":
    unittest.main()
