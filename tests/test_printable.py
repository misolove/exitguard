"""네트워크에서 온 문자열의 제어문자 처리 (godam 실제 사례: QUIC SNI 끝 NUL 패딩으로 curses 가 죽음)."""
import importlib.util, os, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("dash", os.path.join(ROOT, "exitguard", "dash.py"))
dash = importlib.util.module_from_spec(spec); spec.loader.exec_module(dash)


class PrintableTest(unittest.TestCase):
    def test_nul_padding_dropped(self):
        self.assertEqual(dash.printable("news.example\x00\x00\x00 [quic]"), "news.example [quic]")

    def test_escape_and_bidi_replaced(self):
        self.assertEqual(dash.printable("a\x1b[2Jb‮c\r\n"), "a?[2Jb?c??")

    def test_korean_and_emoji_kept(self):
        self.assertEqual(dash.printable("한글 도메인.example ✅"), "한글 도메인.example ✅")


if __name__ == "__main__":
    unittest.main()
