"""snapshot 의 detection: 알림 0건이 '안전'인지 '탐지 불가'인지 구분하는 지표."""
import time, unittest
from datetime import datetime
from unittest.mock import patch
from test_dash_layout import load_dash

TAILNET = "[100.64.0.0/10,fd7a:115c:a1e0::/48]"


class DetectionHealthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()
        cls.core = cls.d.core

    def model(self, alert_age=None, loaded=53363, failed=0):
        m = self.core.Model()
        now = time.time()
        if alert_age is not None:
            m.alerts = [{"ts": datetime.fromtimestamp(now - alert_age).isoformat(), "kind": "ids-alert", "level": "LOW"},
                        {"ts": datetime.fromtimestamp(now).isoformat(), "kind": "dns-dga", "level": "MEDIUM"}]
        if loaded is not None:
            m.stats = {"detect": {"engines": [{"last_reload": "2026-11-04T01:41:38+09:00",
                                               "rules_loaded": loaded, "rules_failed": failed}]}}
        return m, now

    def health(self, home=TAILNET, **kw):
        m, now = self.model(**kw)
        with patch.object(self.core, "DEMO", False), patch.object(self.core.ids_health, "yaml_home_net", lambda: home):
            return self.core.detection_health(m, now)

    def test_ok_with_recent_signature(self):
        h = self.health(alert_age=180)
        self.assertEqual(h["state"], "ok")
        self.assertEqual(h["rules_loaded"], 53363)
        self.assertTrue(h["home_net_ok"])
        self.assertAlmostEqual(h["age_s"], 180, delta=2)

    def test_quiet_or_unknown_is_warn_not_ok(self):
        self.assertEqual(self.health(alert_age=13 * 3600)["state"], "warn")   # 12시간 넘게 조용
        self.assertEqual(self.health(alert_age=None)["state"], "warn")        # 시그니처 기록 없음 (dns-dga 는 제외)
        self.assertEqual(self.health(alert_age=60, loaded=None)["state"], "warn")

    def test_bad_home_net_or_rules(self):
        h = self.health(home="[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]", alert_age=60)
        self.assertEqual((h["state"], h["home_net_ok"]), ("bad", False))     # 2026-11-02 사고 상태
        self.assertEqual(self.health(alert_age=60, failed=2)["state"], "bad")
        self.assertEqual(self.health(alert_age=60, loaded=10)["state"], "bad")
        self.assertIsNone(self.health(home=None, alert_age=60)["home_net_ok"])  # yaml 을 못 읽으면 판단 안 함

    def test_demo_snapshot_has_detection(self):
        s = self.d.snapshot(self.d.DemoModel())
        self.assertEqual(s["detection"]["state"], "ok")
        self.assertIsNone(s["detection"]["home_net_ok"])


if __name__ == "__main__":
    unittest.main()
