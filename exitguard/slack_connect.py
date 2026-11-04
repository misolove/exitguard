#!/usr/bin/env python3
"""Slack 연결 ("Add to Slack" OAuth). root 로 잠깐만 실행되고, 상시 웹 대시보드는 읽기 전용 그대로 둔다.

사용 (exitguardctl 이 sudo 로 부른다):
  exitguardctl slack-connect --setup   Slack 앱 만들기 링크 출력 + Client ID/Secret 저장 (/etc/exitguard/slack-app.json, 0600)
  exitguardctl slack-connect           5분 동안만 콜백을 받는 창구를 열고, 승인되면 확인 후 webhook 저장·테스트·감시 재시작

흐름: 브라우저 → slack.com 승인(채널 선택) → https://<이 머신>.<tailnet>.ts.net:8443/slack/callback (tailscale serve)
      → 127.0.0.1 임시 서버 → oauth.v2.access 로 코드 교환 → 터미널에서 워크스페이스·채널 확인 → config.json 저장.
콜백 주소는 tailnet 안에서만 열린다 (funnel 아님). state 값으로 다른 승인 응답을 거부한다.
"""
import getpass, hmac, json, os, secrets, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

APP_FILE = os.environ.get("EXITGUARD_SLACK_APP", "/etc/exitguard/slack-app.json")
CFG_PATH = os.environ.get("EXITGUARD_CONFIG", "/etc/exitguard/config.json")
PENDING = os.environ.get("EXITGUARD_SLACK_PENDING", "/run/exitguard/slack-connect.json")
SERVE_PORT = 8443            # tailscale serve 가 허용하는 HTTPS 포트 중 하나 (443 은 다른 용도로 비워 둔다)
LOCAL_PORT = 8181
CALLBACK = "/slack/callback"
TIMEOUT = 300
AUTHORIZE = "https://slack.com/oauth/v2/authorize"


def tailnet_host():
    """이 머신의 MagicDNS 이름 (끝의 점 제거). 없으면 None."""
    try:
        st = json.loads(subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10).stdout)
        return (st.get("Self", {}).get("DNSName") or "").rstrip(".") or None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def redirect_uri(host):
    return f"https://{host}:{SERVE_PORT}{CALLBACK}"


def manifest_url(redirect):
    """Slack 앱 만들기 화면을 설정이 채워진 채로 여는 링크 (incoming-webhook 권한 하나만)."""
    # incoming-webhook 권한은 봇 사용자가 있어야 manifest 검증을 통과한다
    manifest = {"display_information": {"name": "ExitGuard", "description": "ExitGuard 이상징후 알림"},
                "features": {"bot_user": {"display_name": "ExitGuard", "always_online": False}},
                "oauth_config": {"redirect_urls": [redirect], "scopes": {"bot": ["incoming-webhook"]}},
                "settings": {"org_deploy_enabled": False, "socket_mode_enabled": False, "token_rotation_enabled": False}}
    return "https://api.slack.com/apps?new_app=1&manifest_json=" + urllib.parse.quote(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))


def authorize_url(client_id, redirect, state):
    return AUTHORIZE + "?" + urllib.parse.urlencode(
        {"client_id": client_id, "scope": "incoming-webhook", "redirect_uri": redirect, "state": state})


def check_callback(query, state):
    """콜백 쿼리 → (code, None) 또는 (None, 오류 설명)."""
    q = urllib.parse.parse_qs(query)
    if not hmac.compare_digest((q.get("state") or [""])[0], state):
        return None, "state 불일치 (다른 승인 응답)"
    if q.get("error"):
        return None, "Slack 에서 거절됨: " + q["error"][0]
    code = (q.get("code") or [""])[0]
    return (code, None) if code else (None, "code 없음")


def exchange(app, code, redirect):
    """oauth.v2.access → (webhook_url, 팀 이름, 채널). 실패하면 RuntimeError."""
    data = urllib.parse.urlencode({"client_id": app["client_id"], "client_secret": app["client_secret"],
                                   "code": code, "redirect_uri": redirect}).encode()
    with urllib.request.urlopen("https://slack.com/api/oauth.v2.access", data=data, timeout=15) as r:
        res = json.loads(r.read())
    hook = res.get("incoming_webhook") or {}
    if not res.get("ok") or not hook.get("url"):
        raise RuntimeError("Slack 응답 오류: " + str(res.get("error") or "incoming_webhook 없음"))
    return hook["url"], (res.get("team") or {}).get("name", "?"), hook.get("channel", "?")


def save_webhook(url, path=None):
    """config.json 의 notify.webhook_url 만 바꾸고 나머지 설정·권한은 유지 (임시 파일 → 원자적 교체)."""
    path = path or CFG_PATH
    with open(path) as f:
        cfg = json.load(f)
    cfg.setdefault("notify", {})["webhook_url"] = url
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".config.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2); f.write("\n")
        os.chmod(tmp, st.st_mode & 0o777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp); raise


def write_pending(url, expires, path=None):
    """웹 대시보드가 '연결' 버튼을 보여 줄 수 있게 승인 주소를 잠깐 공개 (0644, 만료 시각 포함)."""
    path = path or PENDING
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"authorize_url": url, "expires": expires}, f)
    os.chmod(tmp, 0o644); os.replace(tmp, path)


def read_pending(path=None, now=None):
    """만료 전이고 slack.com 승인 주소일 때만 {"authorize_url", "expires"}. 아니면 None. (웹 대시보드용)"""
    try:
        with open(path or PENDING) as f:
            p = json.load(f)
        url, exp = str(p["authorize_url"]), float(p["expires"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if exp <= (now or time.time()) or not url.startswith(AUTHORIZE + "?"):
        return None
    return {"authorize_url": url, "expires": exp}


PAGE = """<!doctype html><meta charset="utf-8"><title>ExitGuard</title>
<body style="font:16px sans-serif;background:#0d1117;color:#e6edf3;padding:40px"><h1>{0}</h1><p>{1}</p></body>"""


def setup():
    host = tailnet_host()
    if not host:
        sys.exit("Tailscale MagicDNS 이름을 찾지 못했습니다 (tailscale status 확인)")
    red = redirect_uri(host)
    print("1) 아래 링크를 브라우저에서 열고 워크스페이스를 고른 뒤 Create 를 누르세요 (설정이 채워져 있습니다):\n")
    print("   " + manifest_url(red) + "\n")
    print("2) 앱 화면의 Basic Information > App Credentials 에서 Client ID 와 Client Secret 을 복사해 아래에 입력하세요.")
    print("   (Secret 은 화면에 표시되지 않습니다. 채팅·Git 에 붙여 넣지 마세요)\n")
    cid = input("Client ID: ").strip()
    sec = getpass.getpass("Client Secret: ").strip()
    if not cid or not sec:
        sys.exit("입력이 비어 있어 저장하지 않았습니다")
    os.makedirs(os.path.dirname(APP_FILE), exist_ok=True)
    fd = os.open(APP_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_id": cid, "client_secret": sec, "redirect_uri": red}, f)
    os.chmod(APP_FILE, 0o600)
    print(f"\n저장: {APP_FILE} (0600). 이제 'sudo exitguardctl slack-connect' 로 연결하세요.")


def connect():
    try:
        with open(APP_FILE) as f:
            app = json.load(f)
    except OSError:
        sys.exit("Slack 앱 정보가 없습니다. 먼저 'sudo exitguardctl slack-connect --setup'")
    host = tailnet_host()
    red = redirect_uri(host) if host else app.get("redirect_uri")
    if not red:
        sys.exit("Tailscale MagicDNS 이름을 찾지 못했습니다")
    state = secrets.token_urlsafe(24)
    url = authorize_url(app["client_id"], red, state)
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path != CALLBACK:
                self.send_error(404); return
            code, err = check_callback(query, state)
            if code and "code" not in result:
                result["code"] = code
                title, text = "승인 받음", "서버 터미널로 돌아가 워크스페이스·채널을 확인하세요. 이 창은 닫아도 됩니다."
            else:
                title, text = "연결 실패", err or "이미 처리된 요청입니다."
            body = PAGE.format(title, text).encode()
            self.send_response(200 if code else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", LOCAL_PORT), Handler)
    srv.timeout = 1
    serve_on = subprocess.run(["tailscale", "serve", "--bg", f"--https={SERVE_PORT}", f"http://127.0.0.1:{LOCAL_PORT}"],
                              capture_output=True, text=True)
    if serve_on.returncode != 0:
        srv.server_close()
        sys.exit("tailscale serve 실패: " + (serve_on.stderr or serve_on.stdout).strip()[:300])
    expires = time.time() + TIMEOUT
    write_pending(url, expires)
    try:
        print("Slack 연결 대기 중 (5분). 웹 대시보드의 'Slack에 연결' 버튼을 누르거나 이 주소를 여세요:\n")
        print("   " + url + "\n")
        while "code" not in result and time.time() < expires:
            srv.handle_request()
    finally:
        srv.server_close()
        subprocess.run(["tailscale", "serve", f"--https={SERVE_PORT}", "off"], capture_output=True)
        try:
            os.unlink(PENDING)
        except OSError:
            pass
    if "code" not in result:
        sys.exit("시간 안에 승인되지 않아 종료했습니다 (설정 변경 없음)")
    hook, team, channel = exchange(app, result["code"], red)
    ans = input(f"\n워크스페이스 '{team}' 의 채널 '{channel}' 로 알림을 보내도록 저장할까요? [y/N] ").strip().lower()
    if ans != "y":
        sys.exit("저장하지 않았습니다 (설정 변경 없음)")
    save_webhook(hook)
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    from common import Notifier, load_config
    Notifier(load_config(CFG_PATH))._webhook("ExitGuard: Slack 연결 테스트 메시지입니다. 이 메시지가 보이면 알림이 연결된 것입니다.")
    subprocess.run(["systemctl", "restart", "exitguard-watch.service"], check=False)
    print(f"저장했습니다. '{channel}' 채널에 테스트 메시지를 보냈고 감시 서비스를 재시작했습니다.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("root 로 실행하세요: sudo exitguardctl slack-connect")
    setup() if sys.argv[1:2] == ["--setup"] else connect()
