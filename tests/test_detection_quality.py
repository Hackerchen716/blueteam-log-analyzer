"""Detection-quality regression gate.

Runs the labeled corpus through ``scripts/eval_detection.py`` and enforces a
floor on recall / precision / false-positive rate so detection quality cannot
silently regress. The corpus mixes real attacks with *adversarial benign*
traffic, so the FP-rate gate is meaningful.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "fixtures" / "detection_quality" / "cases.jsonl"

_spec = importlib.util.spec_from_file_location("eval_detection", ROOT / "scripts" / "eval_detection.py")
_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_eval)

# 阈值低于当前实测值（recall=1.0 / precision=1.0 / fp_rate=0.0），留少量余量以容纳
# 后续新增的疑难样本，同时仍能拦住真实的质量回退。
MIN_RECALL = 0.95
MIN_PRECISION = 0.95
MAX_FP_RATE = 0.07


class DetectionQualityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = _eval.evaluate(_eval.load_cases(CASES))
        cls.summary = cls.report["summary"]

    def test_corpus_is_non_trivial(self):
        # 既有真阳也有对抗性良性，FP 率才有意义。
        self.assertGreaterEqual(self.summary["tp"] + self.summary["fn"], 20)
        self.assertGreaterEqual(self.summary["tn"] + self.summary["fp"], 12)

    def test_recall_floor(self):
        self.assertGreaterEqual(
            self.summary["recall"], MIN_RECALL,
            f"漏报: {self.report['false_negatives']}",
        )

    def test_precision_floor(self):
        self.assertGreaterEqual(
            self.summary["precision"], MIN_PRECISION,
            f"误报: {self.report['false_positives']}",
        )

    def test_false_positive_rate_ceiling(self):
        self.assertLessEqual(
            self.summary["fp_rate"], MAX_FP_RATE,
            f"误报: {self.report['false_positives']}",
        )

    def test_file_based_manifest_path(self):
        # 锁住"用真实日志文件评测"的 file/manifest 路径与示例样本。
        manifest = ROOT / "tests" / "fixtures" / "detection_quality" / "manifest.example.jsonl"
        report = _eval.evaluate(_eval.load_cases(manifest))
        self.assertEqual(report["summary"]["fp"], 0, report["false_positives"])
        self.assertEqual(report["summary"]["fn"], 0, report["false_negatives"])
        self.assertGreaterEqual(report["summary"]["tp"], 1)


if __name__ == "__main__":
    unittest.main()
