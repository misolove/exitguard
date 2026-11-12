"""purpose.py: 목적지 이름 → 짧은 용도 설명 (고정 표, 가장 구체적인 것 우선)."""
import importlib.util, json, os, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("purpose", os.path.join(ROOT, "exitguard", "purpose.py"))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class PurposeTest(unittest.TestCase):
    def test_most_specific_wins(self):
        self.assertEqual(p.purpose("speeddials.opera.com"), "Opera 새 탭 바로가기 타일")
        self.assertEqual(p.purpose("www.opera.com"), "Opera 브라우저")
        self.assertEqual(p.purpose("ecs.office.com"), "Office 앱 설정·기능 업데이트")

    def test_cloud_log_service(self):
        long = "proj-xtrace-" + "0" * 32 + "-cn-beijing.cn-beijing.log.aliyuncs.com"
        self.assertEqual(p.purpose(long), "앱 사용 기록 전송 (알리바바·중국)")
        self.assertEqual(p.purpose("oss-cn-hangzhou.aliyuncs.com"), "알리바바 클라우드 (중국 앱 서버)")

    def test_labels_and_case(self):
        self.assertEqual(p.purpose("openapi.tossinvest.com [tls]"), "토스증권 시세·주문")
        self.assertEqual(p.purpose("API.Anthropic.COM."), "Claude (Anthropic)")

    def test_unknown_and_lookalikes(self):
        self.assertIsNone(p.purpose("example.org"))
        self.assertIsNone(p.purpose("evilopera.com"))           # 'opera.com' 으로 끝나도 다른 도메인
        self.assertIsNone(p.purpose("opera.com.evil.example"))
        self.assertIsNone(p.purpose("102.67.165.90"))
        self.assertIsNone(p.purpose(None))

    def test_table_is_clean(self):
        for k, v in p.PURPOSE.items():
            self.assertEqual(k, k.lower().strip("."), k)
            self.assertTrue(0 < len(v) <= 30, v)

    def test_guesses_are_marked(self):
        self.assertTrue(p.purpose("api.firwinds.site").startswith("추정: "))
        self.assertTrue(p.purpose("cdn.cr-relay.com").startswith("추정: "))

    def test_local_names(self):
        self.assertEqual(p.purpose("godam"), "내부 기기 이름 조회")
        self.assertEqual(p.purpose("godam.example-tailnet.ts.net"), "Tailscale 내부 기기")

    def test_unknown_lister(self):
        lines = ['{"event_type":"tls","tls":{"sni":"a.mystery.example"}}',
                 '{"event_type":"dns","dns":{"rrname":"b.mystery.example."}}',
                 '{"event_type":"tls","tls":{"sni":"api.anthropic.com"}}',
                 '{"event_type":"http","http":{"hostname":"203.0.113.9"}}',
                 '{"event_type":"tls","tls":{"sni":"x.shop.co.kr"}}', 'not json "sni"']
        self.assertEqual(dict(p.unknown(lines)), {"mystery.example": 2, "shop.co.kr": 1})


class LocalTableTest(unittest.TestCase):
    """공개 저장소에 둘 수 없는 내 기기·서비스(IP·사설 도메인)는 그 호스트의 로컬 표로."""
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "purpose-local.json")
        self.old = p.LOCAL_PATH
        p.LOCAL_PATH = self.path
        p._local.update(checked=0.0, mtime=None, table={})

    def tearDown(self):
        p.LOCAL_PATH = self.old
        p._local.update(checked=0.0, mtime=None, table={})
        self.dir.cleanup()

    def write(self, obj):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))
        p._local["checked"] = 0.0

    def test_ip_and_domain(self):
        self.write({"203.0.113.10": "아파트 주차 앱 (평문 로그인)", "Home.Example.LAN": "집 NAS", "example.com": "덮어쓴 설명"})
        self.assertEqual(p.purpose(None, ip="203.0.113.10"), "아파트 주차 앱 (평문 로그인)")
        self.assertEqual(p.purpose("203.0.113.10"), "아파트 주차 앱 (평문 로그인)")       # 이름 칸에 IP 만 있을 때
        self.assertEqual(p.purpose("nas.home.example.lan [tls]"), "집 NAS")
        self.assertEqual(p.purpose("www.example.com"), "덮어쓴 설명")                      # 로컬 표가 먼저
        self.assertEqual(p.purpose("api.anthropic.com", ip="198.51.100.9"), "Claude (Anthropic)")
        self.assertIsNone(p.purpose(None, ip="198.51.100.9"))

    def test_missing_or_broken_is_ignored(self):
        self.assertIsNone(p.purpose(None, ip="203.0.113.10"))                           # 파일 없음
        self.write("{ 깨진 json")
        self.assertIsNone(p.purpose(None, ip="203.0.113.10"))
        self.write({"203.0.113.10": 5, "203.0.113.11": "  ", "203.0.113.12": "가" * 50})
        self.assertIsNone(p.purpose(None, ip="203.0.113.10"))                           # 문자열만
        self.assertIsNone(p.purpose(None, ip="203.0.113.11"))
        self.assertEqual(len(p.purpose(None, ip="203.0.113.12")), 30)
        self.assertEqual(p.purpose("godam"), "내부 기기 이름 조회")                     # 기본 규칙은 그대로


class DerpTableTest(unittest.TestCase):
    """Tailscale 중계 서버는 IP 로만 접속한다 → watch 가 써 둔 목록으로 용도를 붙인다."""
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "derp-ips.json")
        self.old = p.DERP_PATH
        p.DERP_PATH = self.path
        p._derp.update(checked=0.0, mtime=None, table=set())

    def tearDown(self):
        p.DERP_PATH = self.old
        p._derp.update(checked=0.0, mtime=None, table=set())
        self.dir.cleanup()

    def write(self, text):
        with open(self.path, "w") as f:
            f.write(text)
        p._derp["checked"] = 0.0

    def test_derp_ip(self):
        self.write(json.dumps(["198.51.100.7", "2001:DB8::7"]))
        self.assertEqual(p.purpose(None, ip="198.51.100.7"), p.DERP_LABEL)
        self.assertEqual(p.purpose("198.51.100.7"), p.DERP_LABEL)                      # 이름 칸에 IP 만
        self.assertEqual(p.purpose(None, ip="2001:db8::7"), p.DERP_LABEL)
        self.assertIsNone(p.purpose(None, ip="192.0.2.50"))

    def test_missing_or_broken_is_ignored(self):
        self.assertIsNone(p.purpose(None, ip="198.51.100.7"))
        self.write("{ 깨진")
        self.assertIsNone(p.purpose(None, ip="198.51.100.7"))
        self.write(json.dumps({"198.51.100.7": 1}))                                    # 목록이 아니면 무시
        self.assertIsNone(p.purpose(None, ip="198.51.100.7"))


if __name__ == "__main__":
    unittest.main()
