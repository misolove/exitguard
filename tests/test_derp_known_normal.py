"""watch.py: Tailscale 중계(DERP) 서버로의 연결 확인(GET /generate_204)은 알림으로 내지 않는다."""
import importlib.util, json, os, sys, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "exitguard"))
spec = importlib.util.spec_from_file_location("watch", os.path.join(ROOT, "exitguard", "watch.py"))
w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)

DERP_MAP = json.dumps({"Regions": {"7": {"RegionCode": "tok", "Nodes": [
    {"HostName": "derp7x.example", "IPv4": "198.51.100.7", "IPv6": "2001:db8::7"}]},
    "9": {"Nodes": [{"IPv4": "203.0.113.9"}]}}})


def ev(dst, url):
    return {"event_type": "alert", "src_ip": "100.64.0.11", "dest_ip": dst,
            "http": {"hostname": dst, "url": url}, "alert": {"signature": "ET USER_AGENTS Go HTTP Client User-Agent"}}


class DerpTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(w.derp_ips(DERP_MAP), {"198.51.100.7", "2001:db8::7", "203.0.113.9"})
        self.assertEqual(w.derp_ips("not json"), set())
        self.assertEqual(w.derp_ips("{}"), set())

    def test_only_generate_204_to_derp(self):
        derp = w.derp_ips(DERP_MAP)
        self.assertTrue(w.is_derp_check(ev("198.51.100.7", "/generate_204?t=1"), derp))
        self.assertTrue(w.is_derp_check(ev("203.0.113.9", "/generate_204"), derp))
        self.assertFalse(w.is_derp_check(ev("198.51.100.7", "/admin"), derp))            # 다른 요청은 그대로 알림
        self.assertFalse(w.is_derp_check(ev("192.0.2.50", "/generate_204"), derp))       # 중계 서버가 아니면 알림
        self.assertFalse(w.is_derp_check(ev("198.51.100.7", "/generate_204x"), derp))
        self.assertFalse(w.is_derp_check(ev("198.51.100.7", "/generate_204"), set()))    # 목록 없으면 거르지 않음
        self.assertFalse(w.is_derp_check({"dest_ip": "198.51.100.7"}, derp))


if __name__ == "__main__":
    unittest.main()
