from _support import *

class LogSourceRegressionTests(unittest.TestCase):
    def test_log_source_priorities_capture_ir_collection_order(self):
        sources = [(item.name, item.importance) for item in LOG_SOURCE_PRIORITIES]
        categories = {item.category for item in LOG_SOURCE_PRIORITIES}
        priorities = [item.priority for item in LOG_SOURCE_PRIORITIES]

        self.assertGreaterEqual(len(sources), 40)
        self.assertEqual(sources[:4], [
            ("WAF / Web 安全网关日志", "极高"),
            ("CDN / SLB / 反向代理访问日志", "极高"),
            ("Web 服务器 access.log", "极高"),
            ("业务应用日志", "极高"),
        ])
        self.assertEqual(priorities[:18], ["P0"] * 18)
        self.assertIn(("VPN / SSL VPN / 零信任登录日志", "极高"), sources)
        self.assertIn(("云平台审计日志", "极高"), sources)
        self.assertIn(("Webshell 查杀 / 文件完整性日志", "高"), sources)
        self.assertIn("云与容器", categories)
        self.assertIn("数据与中间件", categories)
        self.assertIn("平台与运营", categories)

    def test_log_source_priority_table_is_markdown(self):
        table = format_log_source_priorities()

        self.assertIn("| 优先级 | 类别 | 类型 | 日志源 | 重要性 | 必备字段 | 研判重点 | 建议时间窗 |", table)
        self.assertIn("| P0 | 边界入口 | 日志源 | WAF / Web 安全网关日志 | 极高 |", table)
        self.assertIn("| P1 | Web 与应用 | 日志源 | Web 服务器 error.log | 高 |", table)
        self.assertIn("云账号接管", table)
        self.assertIn("P0=第一轮必采", table)
