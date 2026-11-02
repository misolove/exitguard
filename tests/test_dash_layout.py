#!/usr/bin/env python3
"""dash.py 화면 폭별 스모크 테스트 (표준 라이브러리만, 데모 모드).

- pty 로 폭 40/60/80/150 터미널을 만들어 curses 대시보드를 띄우고, 예외 없이 그려진 뒤 q 로 종료되는지 확인
- 같은 확인을 root 모드(IS_ROOT=True)로도 수행. 테스트 프로세스 안에서만 바꾸고 nft 조치는 막는다
- 가상 화면(가짜 curses 창)에 draw() 를 그려 폭별 축약 표기 내용과 "모든 줄이 화면 폭 안" 을 확인 (root/일반)
- --demo --text 출력이 기준 파일(tests/golden_text_demo.txt)과 같은지 확인 (시각만 가림)

실행: python3 -m unittest discover -s tests -v   또는   python3 tests/test_dash_layout.py
"""
import importlib.util, fcntl, os, pty, re, select, signal, struct, subprocess, sys, termios, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "exitguard", "dash.py")
GOLDEN = os.path.join(ROOT, "tests", "golden_text_demo.txt")
UTF8 = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"   # macOS 는 C.UTF-8 로케일이 없을 수 있다
ENV = dict(os.environ, TERM="xterm-256color", LANG=UTF8, LC_ALL=UTF8)
for k in ("LINES", "COLUMNS"):
    ENV.pop(k, None)


# root 모드 실행용: dash 를 모듈로 읽어 IS_ROOT 만 켜고, 실제 nft/pcap 조치(UI.action)는 아무것도 하지 않게 막는다.
# 데모 모델은 nft 를 읽지 않으므로 시스템에는 어떤 명령도 실행되지 않는다.
ROOT_RUNNER = r"""
import importlib.util, sys
sys.argv = [sys.argv[1], "--demo"]
spec = importlib.util.spec_from_file_location("dash", sys.argv[0])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
d.IS_ROOT = True
d.UI.action = lambda self, key: setattr(self.m, "msg", "테스트: 조치 비활성")
d.main()
"""


def load_dash():
    """dash.py 를 데모 모드로 모듈 로드 (DEMO 는 import 시점의 sys.argv 로 정해진다)."""
    saved = sys.argv
    sys.argv = [DASH, "--demo"]
    try:
        spec = importlib.util.spec_from_file_location("dash_under_test", DASH)
        d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
    finally:
        sys.argv = saved
    return d


def run_tui(cols, rows=24, settle=2.5, timeout=10.0, root=False):
    """pty 에서 대시보드를 띄우고 settle 초 뒤 'q' 를 보낸다. (종료코드, 출력 바이트) 반환."""
    argv = [sys.executable, "-c", ROOT_RUNNER, DASH] if root else [sys.executable, DASH, "--demo"]
    pid, fd = pty.fork()
    if pid == 0:   # 자식: 터미널 크기는 부모가 정한 pty 크기를 따른다
        try:
            os.execve(sys.executable, argv, ENV)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    out = b""; start = time.time(); sent = False; status = None
    try:
        while time.time() - start < timeout:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:      # 자식 종료 후 EIO
                    data = b""
                if not data:
                    break
                out += data
            if not sent and time.time() - start >= settle:
                os.write(fd, b"q"); sent = True
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st; break
        # macOS 는 자식 종료 시 pty 가 EIO 대신 EOF 를 먼저 돌려줘 루프가 일찍 끝난다: 잠깐 더 기다려 회수
        grace = time.time() + 2.0
        while status is None and time.time() < grace:
            try:
                wpid, st = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break
            if wpid:
                status = st
            else:
                time.sleep(0.05)
        if status is None:
            os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
            return None, out
        return os.waitstatus_to_exitcode(status), out
    finally:
        os.close(fd)


def mask_text(s):
    s = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "YYYY-MM-DD hh:mm:ss", s)
    return re.sub(r"\b\d{2}:\d{2}:\d{2}\b", "hh:mm:ss", s)


class TestNarrowLayout(unittest.TestCase):
    root = False

    def check_width(self, cols):
        code, out = run_tui(cols, root=self.root)
        text = out.decode("utf-8", "replace")
        self.assertIsNotNone(code, f"폭 {cols}: q 를 눌러도 종료되지 않음")
        self.assertNotIn("Traceback", text, f"폭 {cols}: 예외 발생\n{text[-2000:]}")
        self.assertEqual(code, 0, f"폭 {cols}: 종료코드 {code}")
        self.assertIn("ExitGuard", text, f"폭 {cols}: 헤더가 그려지지 않음")
        self.assertIn("demo-", text, f"폭 {cols}: 클라이언트가 그려지지 않음")
        return out

    def test_width_40(self):
        self.check_width(40)

    def test_width_60(self):
        self.check_width(60)

    def test_width_80(self):
        self.check_width(80)

    def test_width_150(self):
        self.check_width(150)


class TestNarrowLayoutRoot(TestNarrowLayout):
    """같은 폭들을 root 모드(단축키 b/u/Q/R/c, 차단·격리 수 표시)로 다시 확인."""
    root = True

    def check_width(self, cols):
        out = super().check_width(cols)
        # 일반 모드의 sudo 안내가 아니라 root 화면이 그려졌는지 (내용 확인은 TestVirtualScreen 에서)
        self.assertNotIn("sudo".encode(), out, f"폭 {cols}: root 모드인데 sudo 안내가 보임")


class FakeWin:
    """curses 창 흉내: addstr 를 표시 폭(한글 2칸) 기준 격자에 기록. 화면 밖으로 넘치면 curses.error."""
    def __init__(self, d, H, W):
        self.d, self.H, self.W = d, H, W
        self.erase()

    def getmaxyx(self):
        return self.H, self.W

    def erase(self):
        self.g = [[" "] * self.W for _ in range(self.H)]

    def refresh(self):
        pass

    def addstr(self, y, x, s, attr=0):
        for ch in s:
            w = self.d.wcwidth(ch)
            if x + w > self.W:
                raise self.d.curses.error("화면 폭 초과")
            self.g[y][x] = ch
            if w == 2:
                self.g[y][x + 1] = ""
            x += w

    def derwin(self, h, w, y, x):
        if h < 2 or w < 2 or y + h > self.H or x + w > self.W:
            raise self.d.curses.error("derwin 범위 밖")
        g = self.g

        class Box:
            def box(_):
                for xx in range(x, x + w):
                    g[y][xx] = g[y + h - 1][xx] = "─"
                for yy in range(y, y + h):
                    g[yy][x] = g[yy][x + w - 1] = "│"
        return Box()

    def rows(self):
        return ["".join(r) for r in self.g]


class TestVirtualScreen(unittest.TestCase):
    """가상 화면에 draw() 를 그려 폭별 축약 표기를 확인한다 (pty 없이, 내용 단위로)."""
    MSG = "차단 203.0.113.9 24h"

    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()
        cls._orig_color = cls.d.curses.color_pair
        cls.d.curses.color_pair = lambda n: 0       # initscr 없이 호출되므로 색은 무시
        cls.m = cls.d.DemoModel(); cls.m.refresh(); cls.m.refresh()

    @classmethod
    def tearDownClass(cls):
        cls.d.curses.color_pair = cls._orig_color

    def render(self, W, root, H=24, msg=""):
        d = self.d
        d.IS_ROOT = root
        self.m.msg = msg
        ui = object.__new__(d.UI); ui.scr = FakeWin(d, H, W); ui.m = self.m; ui.interval = 2.0
        ui.draw()
        return ui.scr.rows()

    def status_rows(self, rows):
        return [r for r in rows[1:3] if "●" in r or "C0" in r or "격리" in r or "root" in r]

    def test_all_rows_fit_every_width(self):
        """38~160칸, root/일반, 메시지 유무 모두: 줄 폭 ≤ 화면 폭, 마지막 줄은 W-1 이하."""
        d = self.d
        for root in (False, True):
            for W in range(38, 161):
                for msg in ("", self.MSG):
                    rows = self.render(W, root, msg=msg)
                    for y, r in enumerate(rows):
                        lim = W - 1 if y == len(rows) - 1 else W
                        self.assertLessEqual(d.wcwidth(r.rstrip()), lim, f"root={root} W={W} y={y}: {r!r}")

    def test_root_status_shows_block_counts(self):
        nb = len(self.m.nft["blocked"]); nq = len(self.m.nft["quar"])
        for W in (38, 40, 60, 80, 100, 129, 150):
            st = " ".join(self.status_rows(self.render(W, True)))
            self.assertRegex(st, rf"차단 ?{nb} +격리 ?{nq}", f"W={W}: {st!r}")
            self.assertNotIn("root 필요", st, f"W={W}")
            self.assertNotIn("조치: root", st, f"W={W}")

    def test_root_footer_variants(self):
        expect = {
            150: " q 종료  +/- 주기  b 차단  u 해제  Q 격리  R 격리해제  c pcap",
            100: " q 종료  +/- 주기  b 차단  u 해제  Q 격리  R 격리해제  c pcap",
            60: " q종료 +/-주기 b차단 u해제 Q격리 R격리해제 c pcap",
            50: " q종료 +/- b차단 u해제 Q격리 R해제 c캡처",
            40: " q종료 b차단 u해제 Q격리 R해제 c캡처",
            38: " q종료 b차단 u해제 Q격리 R해제 c캡처",
        }
        for W, foot in expect.items():
            self.assertEqual(self.render(W, True)[-1].rstrip(), foot, f"W={W}")

    def test_root_footer_keeps_message(self):
        """조치 결과 메시지가 있으면 단축키 안내를 줄여서라도 메시지는 끝까지 보인다."""
        for W in (38, 40, 50, 60, 80, 100, 150):
            foot = self.render(W, True, msg=self.MSG)[-1]
            self.assertIn(self.MSG, foot, f"W={W}: {foot!r}")
            self.assertTrue(foot.startswith(" q"), f"W={W}: {foot!r}")

    def test_root_client_rate_header(self):
        for W in (40, 60, 80, 150):
            hdr = next(r for r in self.render(W, True) if "기기" in r)
            self.assertIn("속도/s", hdr, f"W={W}")
            self.assertNotIn("5분량", hdr, f"W={W}")

    def test_client_columns_by_width(self):
        for root in (False, True):
            hdr = lambda W: next(r for r in self.render(W, root) if "기기" in r)
            self.assertIn("IP", hdr(80)); self.assertIn("플로우", hdr(80))
            self.assertNotIn("IP", hdr(79)); self.assertIn("플로우", hdr(79))
            h59 = hdr(59)
            self.assertNotIn("IP", h59); self.assertNotIn("플로우", h59); self.assertIn("알림", h59)

    def test_nonroot_footer_and_status(self):
        for W in (40, 60, 80, 150):
            rows = self.render(W, False)
            self.assertIn("sudo", rows[-1], f"W={W}")
            self.assertRegex(" ".join(self.status_rows(rows)), r"root", f"W={W}")


class TestTextOutput(unittest.TestCase):
    def test_text_unchanged(self):
        out = subprocess.run([sys.executable, DASH, "--demo", "--text"], capture_output=True, text=True,
                             env=ENV, timeout=30, check=True).stdout
        with open(GOLDEN, encoding="utf-8") as f:
            self.assertEqual(mask_text(out), f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
