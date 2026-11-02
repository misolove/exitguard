"""ExitGuard 공용 유틸: 설정, 로깅, nft 차단, 알림."""
import ipaddress, json, os, subprocess, sys, time, urllib.request, urllib.parse
from datetime import datetime

CONFIG_PATH = os.environ.get("EXITGUARD_CONFIG", "/etc/exitguard/config.json")
LEVELS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return json.load(f)


def nets(cidrs):
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def ip_in(ip, networks):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in networks)


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------- nft
def nft(*args, check=False):
    r = subprocess.run(["nft", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"nft {' '.join(args)}: {r.stderr.strip()}")
    return r


def _fam(ip):
    return "6" if ":" in ip else "4"


def nft_add(setname, ip, hours):
    timeout = f"{int(hours * 3600)}s"
    r = nft("add", "element", "inet", "exitguard", f"{setname}{_fam(ip)}",
            f"{{ {ip} timeout {timeout} }}")
    return r.returncode == 0, _first(r.stderr)


def _first(err):
    return (err.strip().splitlines() or [""])[0]


def nft_del(setname, ip):
    r = nft("delete", "element", "inet", "exitguard", f"{setname}{_fam(ip)}", f"{{ {ip} }}")
    return r.returncode == 0, _first(r.stderr)


def nft_list_set(setname):
    out = {}
    for fam in ("4", "6"):
        r = nft("-j", "list", "set", "inet", "exitguard", f"{setname}{fam}")
        if r.returncode != 0:
            continue
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue
        for obj in data.get("nftables", []):
            s = obj.get("set")
            if not s:
                continue
            for el in s.get("elem", []) or []:
                if isinstance(el, dict) and "elem" in el:
                    e = el["elem"]
                    out[str(e.get("val"))] = {"expires": e.get("expires"), "counter": e.get("counter")}
                else:
                    out[str(el)] = {}
    return out


# ---------------------------------------------------------------- alert sink
class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg
        self.n = cfg.get("notify", {})
        self.log_dir = cfg.get("log_dir", "/var/log/exitguard")
        os.makedirs(self.log_dir, exist_ok=True)
        self.min_level = LEVELS.get(self.n.get("min_level", "MEDIUM"), 2)
        self.dedupe_sec = int(self.n.get("dedupe_sec", 600))
        self._seen = {}

    def _dedupe(self, key):
        t = time.time()
        # 오래된 키 정리
        if len(self._seen) > 5000:
            self._seen = {k: v for k, v in self._seen.items() if t - v < self.dedupe_sec}
        last = self._seen.get(key)
        self._seen[key] = t
        return last is not None and (t - last) < self.dedupe_sec

    def emit(self, level, kind, title, client=None, dest=None, action=None, details=None, dedupe_key=None):
        rec = {
            "ts": now_iso(), "level": level, "kind": kind, "title": title,
            "client": client, "dest": dest, "action": action, "details": details or {},
        }
        # 항상 jsonl 에 기록
        with open(os.path.join(self.log_dir, "alerts.jsonl"), "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        line = f"[{rec['ts']}] {level:8s} {kind:12s} client={client or '-'} dest={dest or '-'} action={action or '-'} :: {title}"
        with open(os.path.join(self.log_dir, "alerts.log"), "a") as f:
            f.write(line + "\n")
        print(line, flush=True)  # journald

        if LEVELS.get(level, 0) < self.min_level:
            return
        if self._dedupe(dedupe_key or f"{kind}|{client}|{dest}|{title}"):
            return
        text = self._format(rec)
        self._desktop(level, title, text)
        self._webhook(text)
        self._telegram(text)

    def _format(self, r):
        icon = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "ℹ️"}.get(r["level"], "")
        lines = [f"{icon} [ExitGuard/{r['level']}] {r['title']}",
                 f"시각: {r['ts']}",
                 f"클라이언트: {r['client'] or '-'}  →  대상: {r['dest'] or '-'}",
                 f"조치: {r['action'] or '관찰만(보고)'}"]
        for k, v in (r.get("details") or {}).items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)

    def _desktop(self, level, title, text):
        if not self.n.get("desktop"):
            return
        user = self.n.get("desktop_user")
        if not user:
            return
        try:
            uid = subprocess.run(["id", "-u", user], capture_output=True, text=True).stdout.strip()
            if not uid:
                return
            urgency = "critical" if LEVELS.get(level, 0) >= 3 else "normal"
            env = {"DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus", "DISPLAY": ":0"}
            cmd = ["sudo", "-u", user] + [f"{k}={v}" for k, v in env.items()] + \
                  ["notify-send", "-u", urgency, "-a", "ExitGuard", f"ExitGuard {level}: {title}", text]
            subprocess.run(cmd, timeout=5, capture_output=True)
        except Exception:
            pass

    def _webhook(self, text):
        url = self.n.get("webhook_url")
        if not url:
            return
        body = json.dumps({"content": text, "text": text}).encode()
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            print(f"webhook error: {e}", file=sys.stderr, flush=True)

    def _telegram(self, text):
        tg = self.n.get("telegram") or {}
        token, chat = tg.get("bot_token"), tg.get("chat_id")
        if not token or not chat:
            return
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=10).read()
        except Exception as e:
            print(f"telegram error: {e}", file=sys.stderr, flush=True)
