"""웹 대시보드(--demo --web) 와 기존 --demo --text 출력 회귀 테스트. 표준 라이브러리만 사용.
실행: python3 -m unittest discover -s tests -v
"""
import json, os, re, subprocess, sys, unittest, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "exitguard", "dash.py")
GOLDEN = os.path.join(ROOT, "tests", "demo_text.golden")


def mask(text):
    """시각만 다른 부분을 지워 비교 가능하게 한다."""
    text = re.sub(r"\d{2}:\d{2}:\d{2}", "HH:MM:SS", text)
    return re.sub(r"\d{4}-\d{2}-\d{2}", "YYYY-MM-DD", text)


class WebDemoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # --port 0: OS 가 빈 포트를 고르고, 서버가 첫 줄에 실제 URL 을 출력한다
        cls.proc = subprocess.Popen([sys.executable, DASH, "--demo", "--web", "--port", "0"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = cls.proc.stdout.readline()
        m = re.search(r"http://[^\s/]+:\d+/", line)
        if not m:
            cls.proc.kill()
            raise RuntimeError(f"서버 시작 실패: {line!r} {cls.proc.stderr.read()}")
        cls.base = m.group(0)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.proc.stdout.close(); cls.proc.stderr.close()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()

    def test_binds_loopback_by_default(self):
        self.assertTrue(self.base.startswith("http://127.0.0.1:"), self.base)

    def test_snapshot_is_json_with_three_clients(self):
        status, ctype, body = self.get("api/snapshot")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ctype)
        snap = json.loads(body)
        self.assertTrue(snap["demo"])
        names = sorted(c["name"] for c in snap["clients"])
        self.assertEqual(names, ["demo-laptop", "demo-phone", "demo-tablet"])
        for key in ("top_dests", "alerts", "recent"):
            self.assertIsInstance(snap[key], list)
            self.assertTrue(snap[key], f"{key} 가 비어 있음")

    def test_snapshot_has_demo_geo(self):
        snap = json.loads(self.get("api/snapshot")[2])
        geo = snap["geo"]
        self.assertEqual(geo["home"]["city"], "Seoul")
        self.assertTrue(geo["points"], "geo.points 가 비어 있음")
        for p in geo["points"]:
            self.assertTrue(-90 <= p["lat"] <= 90 and -180 <= p["lon"] <= 180, p)
            self.assertRegex(p["ip"], r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.")   # 문서용 대역만
        self.assertTrue(any(p["blocked"] for p in geo["points"]), "차단 목적지가 지도에 없음")

    def test_snapshot_has_chart_data(self):
        snap = json.loads(self.get("api/snapshot")[2])
        ser = snap["series"]
        self.assertEqual(ser["step"], 10)
        self.assertTrue(ser["clients"], "series.clients 가 비어 있음")
        for c in ser["clients"]:
            self.assertEqual(len(c["bytes"]), 60)
        self.assertTrue(snap["protos"] and all(p["bytes"] > 0 for p in snap["protos"]))
        groups = snap["alert_groups"]
        self.assertTrue(groups)
        self.assertEqual(sum(g["count"] for g in groups), sum(snap["alerts_24h"].values()))
        self.assertEqual(groups[0]["level"], "HIGH")   # 등급 높은 묶음이 위로

    def test_geo_links_latest_alert_to_destination(self):
        snap = json.loads(self.get("api/snapshot")[2])
        points = {p["ip"]: p for p in snap["geo"]["points"]}
        matched = 0
        for alert in snap["alerts"]:
            self.assertIn("dest", alert)
            if alert["dest"] in points:
                last = points[alert["dest"]]["last_alert"]
                self.assertIsNotNone(last)
                self.assertGreaterEqual(last["ts"], alert["ts"])
                matched += 1
        self.assertGreater(matched, 0)

    def test_static_parts(self):
        for name, ctype in (("viz.js", "javascript"), ("countries-110m.json", "json"), ("parts.html", "text/html")):
            status, got, body = self.get("static/" + name)
            self.assertEqual(status, 200)
            self.assertIn(ctype, got)
            if name != "countries-110m.json":
                # 외부 리소스 없음 (SVG 네임스페이스 문자열만 예외)
                self.assertNotRegex(body.decode().replace("http://www.w3.org/2000/svg", ""), r"https?://")
        for bad in ("static/../dash.py", "static/%2e%2e/dash.py", "static/", "static/README.md"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self.get(bad)
            self.assertEqual(cm.exception.code, 404)

    def test_index_html_is_self_contained(self):
        status, ctype, body = self.get("")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        html = body.decode()
        self.assertIn("api/snapshot", html)
        self.assertIn('name="viewport"', html)
        self.assertNotRegex(html, r"""(src|href)=["']?(https?:)?//""")   # CDN/외부 리소스 없음

    def test_graphic_dashboard_uses_local_parts(self):
        html = self.get("")[2].decode()
        self.assertIn('<script src="static/viz.js"></script>', html)
        self.assertIn('fetch("static/countries-110m.json")', html)
        for name in ("globe", "line", "levelBars", "alertGroups", "donut"):
            self.assertIn("EGViz." + name + "(", html)
        self.assertNotRegex(html, r"https?://|(?:src|href)=[\"']//")
        self.assertNotIn("innerHTML", html)
        self.assertIn("위치 정보 없음", html)
        self.assertIn("if(!centered)", html)
        for name in ("clients", "dests", "blocked", "risk"):
            self.assertIn('id="count-' + name + '"', html)
        self.assertLess(html.index('id="globe"'), html.index('id="recent"'))
        self.assertIn("recentKeys", html)

    def test_read_only(self):
        for method in ("POST", "PUT", "DELETE"):
            req = urllib.request.Request(self.base + "api/snapshot", data=b"{}", method=method)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=10)
            self.assertEqual(cm.exception.code, 405)
        html = self.get("")[2].decode()
        # 조치 UI 나 GET 이외 요청이 페이지에 없어야 한다
        for pat in (r"<form", r"<button", r"<input", r"method\s*:", r"\bpcap\b", r"\bquarantine\b", r"/api/(block|quar)"):
            self.assertNotRegex(html, pat)

    def test_unknown_path_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base + "api/block", timeout=10)
        self.assertEqual(cm.exception.code, 404)


class TextDemoUnchangedTest(unittest.TestCase):
    def test_demo_text_matches_golden(self):
        out = subprocess.run([sys.executable, DASH, "--demo", "--text"], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(GOLDEN, encoding="utf-8") as f:
            self.assertEqual(mask(out.stdout), f.read())


if __name__ == "__main__":
    unittest.main()
