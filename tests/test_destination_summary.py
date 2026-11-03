import time
import unittest
from test_dash_layout import load_dash


class DestinationSummaryTest(unittest.TestCase):
    def test_counts_unique_ips_without_geo_or_top_ten_limit(self):
        d = load_dash()
        m = d.DemoModel()
        m.geo = lambda: {"home": None, "points": []}
        now = time.time()
        m.flows = [(now, "100.64.0.11", "192.0.2." + str(i), 443, "tcp", 100, "tls")
                   for i in range(1, 13)]
        m.flows += [(now, "100.64.0.11", "192.0.2.1", 80, "tcp", 100, "http"),
                    (now - 130, "100.64.0.11", "192.0.2.99", 443, "tcp", 100, "tls")]
        s = d.snapshot(m)
        self.assertEqual(s["destination_count"], 12)
        self.assertEqual(len(s["top_dests"]), 10)
        self.assertEqual(s["geo"]["points"], [])
        blocked = next(p for p in s["attention_dests"] if p["ip"] == "203.0.113.66")
        self.assertTrue(blocked["blocked"])
        self.assertEqual(blocked["last_alert"]["level"], "HIGH")
