#!/usr/bin/env python3
"""ExitGuard 터미널 대시보드 (curses). 원격 SSH 에서 한 화면으로 상태 파악.
사용: exitguard-top            (일반 사용자: 조회만 / root: 차단·격리 조치 가능)
      exitguard-top --text     (curses 없이 스냅샷 한 번 출력)
      exitguard-top --demo     (가짜 데이터로 화면 시연. --text / --web 와 함께 쓸 수 있음)
      exitguard-top --web [--host 127.0.0.1] [--port 8080]
                               (브라우저용 읽기 전용 대시보드. 조치 기능 없음)

구성: core.py (데이터 엔진, 두 화면 공용) · tui.py (텍스트판) · web.py + static/ (웹판)
"""
import curses, os, sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))   # 설치 위치(/usr/local/lib/exitguard)의 모듈을 쓴다
import core, tui, web
# 테스트·기존 스크립트가 dash.X 로 쓰던 이름
from core import DemoModel, Model, printable, slack_status, snapshot, wcwidth
from tui import UI, text_snapshot
from web import make_web_server


def main():
    m = DemoModel() if core.DEMO else Model()
    if "--web" in sys.argv:
        web.serve_web(m); return
    if "--text" in sys.argv:
        tui.text_snapshot(m); return
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(lambda scr: tui.UI(scr, m).loop())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:   # Ctrl+C 도 q 처럼 조용히 종료
        pass
