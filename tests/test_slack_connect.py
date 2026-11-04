"""slack_connect.py: 승인 주소·앱 만들기 링크·콜백 검증·설정 저장·웹 버튼용 대기 정보 (네트워크·root 없음)."""
import json, os, stat, tempfile, time, unittest, urllib.parse
from unittest.mock import patch
from test_dash_layout import load_dash

HOST = "exit-node.example-tailnet.ts.net"


class SlackConnectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()
        cls.sc = cls.d.core.slack_connect

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_urls(self):
        red = self.sc.redirect_uri(HOST)
        self.assertEqual(red, f"https://{HOST}:8443/slack/callback")
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.sc.authorize_url("123.456", red, "st4te")).query)
        self.assertEqual((q["client_id"], q["scope"], q["redirect_uri"], q["state"]),
                         (["123.456"], ["incoming-webhook"], [red], ["st4te"]))
        m = urllib.parse.urlsplit(self.sc.manifest_url(red))
        self.assertEqual(m.netloc, "api.slack.com")
        manifest = json.loads(urllib.parse.parse_qs(m.query)["manifest_json"][0])
        self.assertEqual(manifest["oauth_config"], {"redirect_urls": [red], "scopes": {"bot": ["incoming-webhook"]}})

    def test_callback_checks_state(self):
        self.assertEqual(self.sc.check_callback("code=abc&state=good", "good"), ("abc", None))
        self.assertIsNone(self.sc.check_callback("code=abc&state=evil", "good")[0])
        self.assertIsNone(self.sc.check_callback("code=abc", "good")[0])
        self.assertIn("거절", self.sc.check_callback("error=access_denied&state=good", "good")[1])
        self.assertIsNone(self.sc.check_callback("state=good", "good")[0])

    def test_save_webhook_keeps_other_settings_and_mode(self):
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w") as f:
            json.dump({"block": {"enabled": True}, "notify": {"min_level": "HIGH", "webhook_url": "old"}}, f)
        os.chmod(path, 0o640)
        self.sc.save_webhook("https://hooks.slack.com/services/" + "T/B/x", path)
        with open(path) as f:
            cfg = json.load(f)
        self.assertEqual(cfg["block"], {"enabled": True})
        self.assertEqual(cfg["notify"]["min_level"], "HIGH")
        self.assertTrue(cfg["notify"]["webhook_url"].endswith("/T/B/x"))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self.assertEqual([n for n in os.listdir(self.tmp.name) if n.startswith(".config.")], [])

    def test_pending_expires_and_only_slack(self):
        path = os.path.join(self.tmp.name, "run", "slack-connect.json")
        url = self.sc.authorize_url("1.2", "https://x/cb", "s")
        self.sc.write_pending(url, time.time() + 60, path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        self.assertEqual(self.sc.read_pending(path)["authorize_url"], url)
        self.assertIsNone(self.sc.read_pending(path, now=time.time() + 120))           # 만료
        self.sc.write_pending("https://evil.example/oauth", time.time() + 60, path)
        self.assertIsNone(self.sc.read_pending(path))                                   # slack.com 승인 주소만
        self.assertIsNone(self.sc.read_pending(os.path.join(self.tmp.name, "none.json")))

    def test_snapshot_field(self):
        self.assertIsNone(self.d.snapshot(self.d.DemoModel())["slack_connect"])          # 데모는 연결 안 함
        path = os.path.join(self.tmp.name, "p.json")
        url = self.sc.authorize_url("1.2", "https://x/cb", "s")
        self.sc.write_pending(url, time.time() + 60, path)
        with patch.object(self.d.core, "DEMO", False), patch.object(self.sc, "PENDING", path):
            self.assertEqual(self.d.snapshot(self.d.DemoModel())["slack_connect"]["authorize_url"], url)


if __name__ == "__main__":
    unittest.main()
