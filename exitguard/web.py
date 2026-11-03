"""ExitGuard 웹판 서버 (읽기 전용). 화면은 static/index.html + static/viz.js, 데이터는 core.snapshot.
같은 Model 을 브라우저로 보여준다. 조치(차단·격리·pcap) 경로는 일부러 두지 않는다: GET 만 처리.
"""
import json, os, sys, time

import core
from core import snapshot


def _opt(name, default):
    """--name VALUE 또는 --name=VALUE."""
    for i, a in enumerate(sys.argv):
        if a == name and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


STATIC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "static")
# 정해진 파일만 내보낸다 (경로 조작 방지). 모두 레포에 들어 있는 파일이고 외부에서 불러오는 것은 없다.
STATIC_FILES = {"viz.js": "text/javascript; charset=utf-8", "countries-110m.json": "application/json",
                "parts.html": "text/html; charset=utf-8"}


def make_web_server(m, host="127.0.0.1", port=8080):
    """읽기 전용 HTTP 서버. GET /, /api/snapshot, /static/<허용 파일> 만 응답하고 나머지 메서드는 405."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    lock = threading.Lock(); state = {"t": 0.0}
    with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:   # 화면은 static/index.html
        page = f.read()

    def current():
        with lock:   # Model 은 스레드 안전하지 않으므로 갱신·집계를 한 번에 하나만
            if time.time() - state["t"] >= 1.0:
                m.refresh(); state["t"] = time.time()
            return json.dumps(snapshot(m), ensure_ascii=False).encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "ExitGuardWeb"
        sys_version = ""

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:; frame-ancestors *")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, page, "text/html; charset=utf-8")
            elif path == "/api/snapshot":
                self._send(200, current(), "application/json; charset=utf-8")
            elif path.startswith("/static/") and path[8:] in STATIC_FILES:
                with open(os.path.join(STATIC_DIR, path[8:]), "rb") as f:
                    self._send(200, f.read(), STATIC_FILES[path[8:]])
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

        do_HEAD = do_GET

        def _readonly(self):
            self._send(405, "읽기 전용 대시보드입니다\n".encode(), "text/plain; charset=utf-8")

        do_POST = do_PUT = do_DELETE = do_PATCH = _readonly

        def log_message(self, fmt, *args):   # 2초 폴링 로그로 터미널을 채우지 않는다
            pass

    import socket

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    srv = Server((host, port), Handler)
    return srv


def serve_web(m):
    host = _opt("--host", "127.0.0.1")
    port = int(_opt("--port", "8080"))
    srv = make_web_server(m, host, port)
    h, p = srv.server_address[:2]
    print(f"ExitGuard web (읽기 전용): http://{h if ':' not in h else '[' + h + ']'}:{p}/" + ("  [demo]" if core.DEMO else ""), flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("주의: 루프백 외 주소에 바인딩됨. 인증이 없으므로 신뢰할 수 있는 네트워크/경로(Tailscale serve 등)에서만 쓰세요.", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
