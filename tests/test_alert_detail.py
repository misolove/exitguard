"""알림 묶음을 눌렀을 때 펼쳐 보이는 값: 쉬운 설명, 목적지·나라, 최근 기록, details 정리."""
import time, unittest
from datetime import datetime
from test_dash_layout import load_dash


class AlertDetailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()
        cls.core = cls.d.core

    def model(self, n=12):
        m = self.core.DemoModel()
        now = time.time()
        m.alerts = [{"ts": datetime.fromtimestamp(now - 60 * i).isoformat(timespec="seconds"), "level": "LOW",
                     "kind": "ids-alert", "title": "ET INFO Observed Example CDN Domain", "client": "100.64.0.11",
                     "dest": "198.51.100.10" if i % 3 else "203.0.113.5", "action": "None",
                     "details": {"signature": "x", "category": "Misc activity", "severity": 3, "sid": 2047712,
                                 "sni": "cdn.example\x00.net‮", "unknown_key": "숨김"}}
                    for i in range(n)]
        return m, now

    def test_group_has_detail(self):
        m, now = self.model()
        g = self.core.alert_groups(m, now - 86400)[0]
        self.assertEqual(g["count"], 12)
        self.assertIn("정보성", g["explain"])
        self.assertIsNone(g["action"])                                   # 문자열 "None" 은 조치 없음
        self.assertEqual(len(g["events"]), 8)                            # 최근 8건만
        self.assertGreaterEqual(g["events"][0]["ts"], g["events"][-1]["ts"])
        self.assertLess(g["first"], g["last"])
        self.assertEqual([(x["ip"], x["count"]) for x in g["dests"]], [("198.51.100.10", 8), ("203.0.113.5", 4)])
        self.assertEqual(g["dests"][0]["country"], "Tokyo")              # 데모는 가짜 좌표표의 이름
        det = g["events"][0]["detail"]
        self.assertEqual(det["sid"], 2047712)
        self.assertEqual(det["sni"], "cdn.example.net?")                 # NUL 제거, 방향 전환 문자 → ?
        self.assertNotIn("unknown_key", det)
        self.assertNotIn("signature", det)                               # 제목과 같으니 생략

    def test_explain_prefixes(self):
        ex = self.core.explain
        self.assertIn("HTTPS", ex("ids-alert", "EXITGUARD HTTP Basic Auth over plaintext"))
        self.assertIn("악성코드", ex("ids-alert", "ET MALWARE Something"))
        self.assertIn("User-Agent", ex("ids-alert", "ET USER_AGENTS Go HTTP Client User-Agent"))
        self.assertIn("오탐", ex("ids-alert", "ET WEB_CLIENT eval String.fromCharCode String Which May Be Malicious"))
        self.assertIn("무작위", ex("dns-dga", "NXDOMAIN 급증"))
        self.assertIsNone(ex("ids-alert", "GPL something new"))

    def test_demo_snapshot_and_country_fallback(self):
        s = self.d.snapshot(self.d.DemoModel())
        g = next(g for g in s["alert_groups"] if g["level"] == "HIGH")
        self.assertEqual(g["events"][0]["detail"]["sni"], "c2.example.org")
        self.assertEqual(g["events"][0]["country"], "São Paulo")
        self.assertTrue(all(a["city"] for a in s["attention_dests"]))   # 지금 흐름이 없어도 나라 표시

    def test_globe_point_last_client(self):
        m = self.d.DemoModel()
        now = time.time()
        m.flows.append((now - 30, "100.64.0.12", "198.51.100.10", 443, "tcp", 100, "tls"))
        m.flows.append((now - 5, "100.64.0.13", "198.51.100.10", 443, "tcp", 100, "tls"))
        pts = {p["ip"]: p for p in self.d.snapshot(m)["geo"]["points"]}
        self.assertEqual(pts["198.51.100.10"]["last_client"]["name"], "demo-tablet")   # 가장 최근 흐름의 기기
        self.assertEqual(pts["198.51.100.10"]["last_client"]["ago"], "5s")
        self.assertEqual(pts["203.0.113.66"]["last_client"]["name"], "demo-phone")     # 흐름 없는 차단 목적지 → 알림의 기기


if __name__ == "__main__":
    unittest.main()
