"""systemd/exitguard-web.service 가 인증 없는 웹을 tailnet 주소에만 여는지 확인 (파일 내용 검사)."""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIT = os.path.join(ROOT, "systemd", "exitguard-web.service")


class WebServiceUnitTest(unittest.TestCase):
    def setUp(self):
        with open(UNIT, encoding="utf-8") as f:
            self.unit = f.read()
        self.exec = next(l for l in self.unit.splitlines() if l.startswith("ExecStart="))

    def test_binds_tailnet_ipv4_only(self):
        self.assertIn("tailscale ip -4", self.exec)
        self.assertIn('100.*) exec', self.exec)
        self.assertIn('--host "$$ip"', self.exec)
        self.assertNotIn("0.0.0.0", self.exec)
        self.assertNotIn("--demo", self.exec)

    def test_unprivileged(self):
        for line in ("DynamicUser=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict"):
            self.assertIn(line + "\n", self.unit)


class GeoIPTimerTest(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, *name.split("/")), encoding="utf-8") as f:
            return f.read()

    def test_monthly_and_confined(self):
        timer = self.read("systemd/exitguard-geoip.timer")
        self.assertIn("OnCalendar=*-*-03 ", timer)
        self.assertIn("Persistent=true", timer)
        unit = self.read("systemd/exitguard-geoip.service")
        self.assertIn("ProtectSystem=strict\n", unit)
        self.assertIn("ReadWritePaths=/var/lib/exitguard\n", unit)
        script = self.read("exitguard/geoip-update.sh")
        self.assertIn("https://download.db-ip.com/free/", script)
        self.assertIn('gzip -t "$TMP"', script)
        self.assertIn('mv "$TMP" "$DB"', script)


if __name__ == "__main__":
    unittest.main()
