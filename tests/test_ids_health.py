"""ids_health.py: suricata.yaml HOME_NET 확인과 규칙 재적재 확인 (가짜 파일, 시스템 명령 없음)."""
import importlib.util, json, os, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("ids_health", os.path.join(ROOT, "exitguard", "ids_health.py"))
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

YAML = """vars:
  address-groups:
    {home}
    #HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
"""


class IdsHealthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_yaml_home_net(self):
        bad = self.write("bad.yaml", YAML.format(home='HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"'))
        good = self.write("good.yaml", YAML.format(home='HOME_NET: "[100.64.0.0/10,fd7a:115c:a1e0::/48]"'))
        self.assertEqual(h.yaml_home_net(bad), "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]")
        self.assertEqual(h.yaml_home_net(good), "[100.64.0.0/10,fd7a:115c:a1e0::/48]")
        self.assertIsNone(h.yaml_home_net(os.path.join(self.tmp.name, "missing.yaml")))

    def eve(self, *engines):
        lines = ['{"event_type":"flow"}']
        for e in engines:
            lines.append(json.dumps({"event_type": "stats", "stats": {"detect": {"engines": [e]}}},
                                    separators=(",", ":")))
        lines.append('{"event_type":"alert"}')
        return self.write("eve.json", "\n".join(lines) + "\n")

    def test_latest_engine_and_reload(self):
        old = {"last_reload": "2026-11-02T07:47:06+09:00", "rules_loaded": 53327, "rules_failed": 0}
        new = {"last_reload": "2026-11-04T01:28:56+09:00", "rules_loaded": 53363, "rules_failed": 0}
        e = h.latest_engine(self.eve(old, new))
        self.assertEqual(e["rules_loaded"], 53363)
        t = h.datetime.fromisoformat("2026-11-04T01:28:50+09:00").timestamp()
        self.assertTrue(h.reload_ok(e, t)[0])
        self.assertFalse(h.reload_ok(old, t)[0])                                    # 아직 반영 전
        self.assertFalse(h.reload_ok(dict(new, rules_failed=3), t)[0])
        self.assertFalse(h.reload_ok(dict(new, rules_loaded=12), t)[0])
        self.assertFalse(h.reload_ok(None, t)[0])
        self.assertIsNone(h.latest_engine(os.path.join(self.tmp.name, "none.json")))

    def test_rules_update_guards_reload(self):
        with open(os.path.join(ROOT, "exitguard", "rules-update.sh")) as f:
            script = f.read()
        self.assertIn('python3 "$H" check-yaml', script)
        self.assertIn('python3 "$H" wait-reload "$since"', script)
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.assertIn("HOME_NET: \"'\"$HOME_NET\"'\"", f.read())


if __name__ == "__main__":
    unittest.main()
