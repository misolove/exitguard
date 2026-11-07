"""purpose.py: 목적지 이름 → 짧은 용도 설명 (고정 표, 가장 구체적인 것 우선)."""
import importlib.util, os, unittest

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


if __name__ == "__main__":
    unittest.main()
