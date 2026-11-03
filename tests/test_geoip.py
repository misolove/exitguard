"""오프라인 GeoIP: 작은 가짜 CSV 로 범위 조회, 설정 읽기, 실제 모드 Model.geo() 확인 (네트워크 없음)."""
import gzip, json, os, tempfile, time, unittest
from unittest.mock import patch
from test_dash_layout import load_dash

# DB-IP Lite 형식: start,end,country. 문서용 대역만 쓴다 (RFC 5737 / RFC 3849).
CSV = """192.0.2.0,192.0.2.127,KR
192.0.2.128,192.0.2.255,KR
198.51.100.0,198.51.100.255,US
203.0.113.0,203.0.113.255,ZZ
2001:db8::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,JP
2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,DE
"""


class GeoIPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()
        cls.g = cls.d.core.geoip
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "dbip-country-lite.csv.gz")
        with gzip.open(cls.db, "wt") as f:
            f.write(CSV)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def settings(self, cfg):
        path = os.path.join(self.tmp.name, "geo.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path

    def test_lookup_ranges(self):
        db = self.g.GeoDB(self.db)
        self.assertEqual(len(db.v4[0]), 3)                       # 이어지는 KR 두 범위는 하나로
        self.assertEqual(db.country("192.0.2.0"), "KR")
        self.assertEqual(db.country("192.0.2.255"), "KR")
        self.assertEqual(db.country("198.51.100.7"), "US")
        self.assertIsNone(db.country("203.0.113.9"))             # ZZ = 예약 대역
        self.assertIsNone(db.country("192.0.3.1"))               # 범위 밖
        self.assertIsNone(db.country("10.0.0.1"))
        self.assertEqual(db.country("2001:db8::1"), "JP")
        self.assertEqual(db.country("2001:db8:1::5"), "DE")
        self.assertIsNone(db.country("2001:db8:2::1"))
        self.assertIsNone(db.country("not-an-ip"))

    def test_plain_csv_and_empty_file(self):
        plain = os.path.join(self.tmp.name, "plain.csv")
        with open(plain, "w") as f:
            f.write('"198.51.100.0","198.51.100.255","US"\n')
        self.assertEqual(self.g.GeoDB(plain).country("198.51.100.1"), "US")
        empty = os.path.join(self.tmp.name, "empty.csv")
        open(empty, "w").close()
        with self.assertRaises(ValueError):
            self.g.GeoDB(empty)

    def test_settings(self):
        self.assertEqual(self.g.load_settings(os.path.join(self.tmp.name, "none.json")),
                         {"db": self.g.DEFAULT_DB, "home": None})
        s = self.g.load_settings(self.settings({"db": "/x.csv", "home": {"lat": "37.5", "lon": 127, "city": "Seoul"}}))
        self.assertEqual(s, {"db": "/x.csv", "home": {"lat": 37.5, "lon": 127.0, "city": "Seoul"}})
        self.assertIsNone(self.g.load_settings(self.settings({"home": {"lat": "x"}}))["home"])

    def test_every_centroid_is_valid(self):
        for cc, (lat, lon, name) in self.g.COUNTRY.items():
            self.assertRegex(cc, r"^[A-Z]{2}$")
            self.assertTrue(-90 <= lat <= 90 and -180 <= lon <= 180, cc)
            self.assertTrue(name, cc)

    def real_model(self, cfg):
        m = self.d.core.Model()
        now = time.time()
        m.flows.extend([(now, "100.64.0.11", "198.51.100.7", 443, "tcp", 500, "tls"),
                        (now, "100.64.0.11", "2001:db8::1", 443, "udp", 300, "quic"),
                        (now, "100.64.0.12", "203.0.113.9", 443, "tcp", 900, "tls"),     # ZZ → 제외
                        (now - 600, "100.64.0.12", "192.0.2.9", 443, "tcp", 100, "tls")])  # 오래됨 → 제외
        m._host("198.51.100.7", "news.example.com")
        with patch.object(self.g, "GEO_CFG", self.settings(cfg)):
            return m.geo()

    def test_model_geo_country_points(self):
        geo = self.real_model({"db": self.db, "home": {"lat": 37.5, "lon": 127.0, "city": "Seoul"}})
        self.assertEqual(geo["home"]["city"], "Seoul")
        self.assertEqual(geo["source"], self.g.ATTRIBUTION)
        pts = {p["ip"]: p for p in geo["points"]}
        self.assertEqual(set(pts), {"198.51.100.7", "2001:db8::1"})
        us = pts["198.51.100.7"]
        self.assertEqual((us["country"], us["lat"], us["lon"]), ("US",) + self.g.COUNTRY["US"][:2])
        self.assertEqual(us["host"], "news.example.com")
        self.assertEqual(us["bytes"], 500)
        self.assertFalse(us["blocked"])

    def test_missing_db_is_empty_not_error(self):
        geo = self.real_model({"db": os.path.join(self.tmp.name, "missing.csv.gz")})
        self.assertEqual(geo, {"home": None, "points": []})

    def test_snapshot_passes_source(self):
        m = self.d.DemoModel()
        m.geo = lambda: {"home": None, "points": [], "source": self.g.ATTRIBUTION}
        self.assertEqual(self.d.snapshot(m)["geo"]["source"], self.g.ATTRIBUTION)
        self.assertIsNone(self.d.snapshot(self.d.DemoModel())["geo"]["source"])


if __name__ == "__main__":
    unittest.main()
