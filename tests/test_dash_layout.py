#!/usr/bin/env python3
"""dash.py 화면 폭별 스모크 테스트 (표준 라이브러리만, 데모 모드).

- pty 로 폭 40/60/80/150 터미널을 만들어 curses 대시보드를 띄우고, 예외 없이 그려진 뒤 q 로 종료되는지 확인
- --demo --text 출력이 기준 파일(tests/golden_text_demo.txt)과 같은지 확인 (시각만 가림)

실행: python3 -m unittest discover -s tests -v   또는   python3 tests/test_dash_layout.py
"""
import fcntl, os, pty, re, select, signal, struct, subprocess, sys, termios, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "exitguard", "dash.py")
GOLDEN = os.path.join(ROOT, "tests", "golden_text_demo.txt")
ENV = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8", LC_ALL="C.UTF-8")
for k in ("LINES", "COLUMNS"):
    ENV.pop(k, None)


def run_tui(cols, rows=24, settle=2.5, timeout=10.0):
    """pty 에서 대시보드를 띄우고 settle 초 뒤 'q' 를 보낸다. (종료코드, 출력 바이트) 반환."""
    pid, fd = pty.fork()
    if pid == 0:   # 자식: 터미널 크기는 부모가 정한 pty 크기를 따른다
        try:
            os.execve(sys.executable, [sys.executable, DASH, "--demo"], ENV)
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
        if status is None:
            try:
                wpid, st = os.waitpid(pid, os.WNOHANG)
                status = st if wpid else None
            except ChildProcessError:
                pass
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
    def check_width(self, cols):
        code, out = run_tui(cols)
        text = out.decode("utf-8", "replace")
        self.assertIsNotNone(code, f"폭 {cols}: q 를 눌러도 종료되지 않음")
        self.assertNotIn("Traceback", text, f"폭 {cols}: 예외 발생\n{text[-2000:]}")
        self.assertEqual(code, 0, f"폭 {cols}: 종료코드 {code}")
        self.assertIn("ExitGuard", text, f"폭 {cols}: 헤더가 그려지지 않음")
        self.assertIn("demo-", text, f"폭 {cols}: 클라이언트가 그려지지 않음")

    def test_width_40(self):
        self.check_width(40)

    def test_width_60(self):
        self.check_width(60)

    def test_width_80(self):
        self.check_width(80)

    def test_width_150(self):
        self.check_width(150)


class TestTextOutput(unittest.TestCase):
    def test_text_unchanged(self):
        out = subprocess.run([sys.executable, DASH, "--demo", "--text"], capture_output=True, text=True,
                             env=ENV, timeout=30, check=True).stdout
        with open(GOLDEN, encoding="utf-8") as f:
            self.assertEqual(mask_text(out), f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
