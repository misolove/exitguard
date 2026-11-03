#!/usr/bin/env python3
"""ExitGuard 터미널 대시보드 (curses). 원격 SSH 에서 한 화면으로 상태 파악.
사용: exitguard-top            (일반 사용자: 조회만 / root: 차단·격리 조치 가능)
      exitguard-top --text     (curses 없이 스냅샷 한 번 출력)
      exitguard-top --demo     (가짜 데이터로 화면 시연. --text / --web 와 함께 쓸 수 있음)
      exitguard-top --web [--host 127.0.0.1] [--port 8080]
                               (브라우저용 읽기 전용 대시보드. 조치 기능 없음)
"""
import collections, curses, ipaddress, json, os, subprocess, sys, time, unicodedata
from datetime import datetime
from urllib.parse import urlsplit

CFG_PATH = os.environ.get("EXITGUARD_CONFIG", "/etc/exitguard/config.json")
EVE = os.environ.get("EXITGUARD_EVE", "/var/log/suricata/eve.json")
ALERTS = "/var/log/exitguard/alerts.jsonl"
HOME = [ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48")]
DEMO = "--demo" in sys.argv
IS_ROOT = os.geteuid() == 0 and not DEMO   # 데모에서는 실제 차단/격리 명령을 막는다


def is_home(ip):
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(a in n for n in HOME)


def human(n, suffix=""):
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1000:
            return f"{n:5.1f}{u}{suffix}" if u != "B" else f"{int(n):5d}{u}{suffix}"
        n /= 1024
    return f"{n:5.1f}P{suffix}"


def wcwidth(s):
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)


def fit(s, w, right=False):
    """표시 폭 w 에 맞춰 자르고 패딩 (한글 2칸)."""
    out, cur = "", 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if cur + cw > w:
            break
        out += ch; cur += cw
    pad = " " * (w - cur)
    return pad + out if right else out + pad


def clip(s, w):
    """표시 폭 w 이하로 자르기만 함 (패딩 없음)."""
    return fit(s, w).rstrip(" ") if wcwidth(s) > w else s


def first_fit(cands, w):
    """후보 문자열 중 표시 폭 w 에 들어가는 첫 번째 (없으면 마지막)."""
    for c in cands:
        if wcwidth(c) <= w:
            return c
    return cands[-1]


def norm_ip(ip):
    try:
        return ipaddress.ip_address(ip).compressed
    except Exception:
        return ip


def ago(ts):
    d = int(time.time() - ts)
    return f"{d}s" if d < 60 else f"{d//60}m" if d < 3600 else f"{d//3600}h"


def run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


class Model:
    def __init__(self):
        self.f = None; self.inode = None
        self.stats = {}
        self.flows = collections.deque(maxlen=20000)     # (ts, client, dst, port, proto, bytes)
        self.dests = collections.deque(maxlen=400)       # (ts, client, label)
        self.last_seen = {}                              # client -> ts
        self.alerts = []; self.alerts_pos = 0
        self.names = {}; self.ts_self = {}; self.ts_peers = {}; self.self_ips = set()
        self.services = {}
        self.nft = {"clients": {}, "blocked": {}, "quar": {}}
        self.rates = {}                                   # client -> (bytes/s) from nft deltas
        self._prev_nft = {}; self._prev_t = 0
        self.slow_t = 0
        self.msg = ""

    # ---- eve.json 증분 읽기
    def _open(self):
        if not os.path.exists(EVE):
            return False
        self.f = open(EVE, "rb")   # 바이너리: 반복 중에도 tell/seek 가능
        self.inode = os.fstat(self.f.fileno()).st_ino
        size = os.path.getsize(EVE)
        self.f.seek(max(0, size - 4 * 1024 * 1024))
        if size > 4 * 1024 * 1024:
            self.f.readline()
        return True

    def read_eve(self):
        if self.f is None and not self._open():
            return
        try:
            st = os.stat(EVE)
            if st.st_ino != self.inode or st.st_size < self.f.tell():
                self.f.close(); self.f = None
                return
        except FileNotFoundError:
            return
        now = time.time()
        while True:
            pos = self.f.tell()
            raw = self.f.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):      # Suricata 가 쓰는 중인 부분 줄: 다음 턴에 다시 읽음
                self.f.seek(pos)
                break
            try:
                ev = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            t = ev.get("event_type")
            try:
                ts = datetime.fromisoformat(ev["timestamp"]).timestamp()
            except Exception:
                ts = now
            if t == "stats":
                self.stats = ev.get("stats", {}); continue
            src, dst = norm_ip(ev.get("src_ip", "")), norm_ip(ev.get("dest_ip", ""))
            if src in self.self_ips or dst in self.self_ips:
                continue
            if is_home(src) and not is_home(dst):
                client, ext, port = src, dst, ev.get("dest_port")
            elif is_home(dst) and not is_home(src):
                client, ext, port = dst, src, ev.get("src_port")
            else:
                continue
            self.last_seen[client] = max(self.last_seen.get(client, 0), ts)
            if t == "flow":
                fl = ev.get("flow", {})
                if fl.get("reason") == "shutdown":   # Suricata 재시작 플러시는 실시간 통계에서 제외
                    continue
                b = fl.get("bytes_toserver", 0) + fl.get("bytes_toclient", 0)
                self.flows.append((ts, client, ext, port, (ev.get("proto") or "").lower(), b, ev.get("app_proto") or ""))
            elif t in ("tls", "quic"):
                sni = (ev.get("tls") or ev.get("quic") or {}).get("sni")
                if sni:
                    self.dests.append((ts, client, f"{sni} [{t}]"))
            elif t == "http":
                h = ev.get("http", {})
                self.dests.append((ts, client, f"{h.get('hostname','?')}{(h.get('url') or '')[:30]} [http]"))
            elif t == "dns":
                d = ev.get("dns", {})
                if d.get("type") in ("query", "request"):
                    name = d.get("rrname") or ((d.get("queries") or [{}])[0].get("rrname"))
                    if name:
                        self.dests.append((ts, client, f"{name} [dns]"))

    def read_alerts(self):
        if not os.path.exists(ALERTS):
            return
        try:
            size = os.path.getsize(ALERTS)
            if size < self.alerts_pos:
                self.alerts_pos = 0; self.alerts = []
            with open(ALERTS) as f:
                f.seek(self.alerts_pos)
                for line in f:
                    try:
                        self.alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                self.alerts_pos = f.tell()
            self.alerts = self.alerts[-500:]
        except Exception:
            pass

    def read_slow(self):
        if time.time() - self.slow_t < 10:
            return
        self.slow_t = time.time()
        out = run(["tailscale", "status", "--json"], 10)
        try:
            st = json.loads(out)
            self.ts_self = st.get("Self", {})
            self.ts_peers = st.get("Peer", {})
            self.self_ips = set(self.ts_self.get("TailscaleIPs") or [])
            for p in list(self.ts_peers.values()) + [self.ts_self]:
                for ip in p.get("TailscaleIPs", []) or []:
                    self.names[ip] = p.get("HostName", "")
        except Exception:
            pass
        for s in ("suricata", "exitguard-watch", "exitguard-nft", "tailscaled"):
            self.services[s] = run(["systemctl", "is-active", s]).strip() or "?"

    def read_nft(self):
        if not IS_ROOT:
            return
        res = {"clients": {}, "blocked": {}, "quar": {}}
        for key, sets in (("clients", ("clients4", "clients6")), ("blocked", ("blocked4", "blocked6")), ("quar", ("quarantine4", "quarantine6"))):
            for s in sets:
                out = run(["nft", "-j", "list", "set", "inet", "exitguard", s])
                try:
                    for obj in json.loads(out).get("nftables", []):
                        for el in (obj.get("set") or {}).get("elem") or []:
                            if isinstance(el, dict):
                                e = el["elem"]; res[key][str(e["val"])] = e
                            else:
                                res[key][str(el)] = {}
                except Exception:
                    pass
        now = time.time()
        if self._prev_t:
            dt = max(now - self._prev_t, 0.5)
            for ip, e in res["clients"].items():
                b = (e.get("counter") or {}).get("bytes", 0)
                pb = (self._prev_nft.get(ip, {}).get("counter") or {}).get("bytes", b)
                self.rates[ip] = max(0, b - pb) / dt
        self._prev_nft = res["clients"]; self._prev_t = now
        self.nft = res

    def refresh(self):
        self.read_slow(); self.read_eve(); self.read_alerts(); self.read_nft()

    # ---- 집계
    def name(self, ip):
        n = self.names.get(ip)
        return f"{n}" if n else ip

    def clients(self, win=300):
        now = time.time()
        rows = {}
        for ts, c, ext, port, proto, b, app in self.flows:
            if now - ts > win:
                continue
            r = rows.setdefault(c, {"bytes": 0, "flows": 0, "dests": set()})
            r["bytes"] += b; r["flows"] += 1; r["dests"].add(ext)
        for c, ts in self.last_seen.items():
            if now - ts <= win:
                rows.setdefault(c, {"bytes": 0, "flows": 0, "dests": set()})
        for ip in self.nft["clients"]:
            rows.setdefault(ip, {"bytes": 0, "flows": 0, "dests": set()})
        out = []
        for c, r in rows.items():
            a24 = sum(1 for a in self.alerts if a.get("client") == c and a.get("level") in ("MEDIUM", "HIGH", "CRITICAL"))
            peer = next((p for p in self.ts_peers.values() if c in (p.get("TailscaleIPs") or [])), {})
            link = "direct" if peer.get("CurAddr") else (f"relay:{peer.get('Relay')}" if peer.get("Relay") else "-")
            cnt = (self.nft["clients"].get(c, {}).get("counter") or {})
            out.append({"ip": c, "name": self.name(c), "bytes": r["bytes"], "flows": r["flows"], "ndest": len(r["dests"]),
                        "alerts": a24, "seen": self.last_seen.get(c, 0), "link": link,
                        "rate": self.rates.get(c), "total": cnt.get("bytes"), "quar": c in self.nft["quar"]})
        out.sort(key=lambda x: -(x["rate"] or 0) * 1e9 - x["bytes"])
        return out

    def geo(self, win=120):
        """목적지 좌표. 실제 모드는 아직 GeoIP 조회가 없어 비어 있다 (데모만 가짜 좌표)."""
        return {"home": None, "points": []}

    def series(self, step=10, n=60):
        """기기별 바이트를 step 초 칸 n 개로 묶는다 (가장 오래된 칸이 앞). 웹 선 그래프용."""
        end = int(time.time() // step * step) + step
        start = end - step * n
        rows = {}
        for ts, c, ext, port, proto, b, app in self.flows:
            if ts >= start:
                rows.setdefault(c, [0] * n)[min(n - 1, int((ts - start) // step))] += b
        out = [{"name": self.name(c), "ip": c, "bytes": v} for c, v in rows.items()]
        out.sort(key=lambda r: -sum(r["bytes"]))
        return {"step": step, "end": end, "clients": out}

    def protos(self, win=300, n=6):
        """app_proto 별 바이트 (상위 n-1 개 + 기타)."""
        now = time.time(); agg = collections.Counter()
        for ts, c, ext, port, proto, b, app in self.flows:
            if now - ts <= win:
                agg[app or proto or "기타"] += b
        top = agg.most_common(n - 1)
        rest = sum(agg.values()) - sum(b for _, b in top)
        return [{"label": k, "bytes": b} for k, b in top] + ([{"label": "기타", "bytes": rest}] if rest else [])

    def top_dests(self, win=120, n=15):
        now = time.time(); agg = collections.Counter(); who = {}
        for ts, c, ext, port, proto, b, app in self.flows:
            if now - ts > win:
                continue
            k = f"{ext}:{port}/{proto}" + (f" {app}" if app else "")
            agg[k] += b; who[k] = c
        return [(k, b, who[k]) for k, b in agg.most_common(n)]

    def recent_dests(self, n=30):
        return list(self.dests)[-n:][::-1]


class DemoModel(Model):
    """가짜 데이터로 화면만 보여주는 모드. Suricata/nftables/tailscale 없이 동작하고 아무것도 차단하지 않는다.
    IP 는 CGNAT 대역의 임의 값과 문서용 대역(RFC 5737), 도메인은 예시용(RFC 2606)만 쓴다."""
    CLIENTS = {"100.64.0.11": "demo-phone", "100.64.0.12": "demo-laptop", "100.64.0.13": "demo-tablet"}
    SITES = [("198.51.100.10", 443, "tcp", "tls", "news.example.com"), ("198.51.100.20", 443, "udp", "quic", "video.example.net"),
             ("203.0.113.5", 443, "tcp", "tls", "mail.example.org"), ("203.0.113.40", 80, "tcp", "http", "update.example.com"),
             ("192.0.2.53", 53, "udp", "dns", "cdn.example.net")]
    # 지도 시연용 가짜 좌표 (위도, 경도, 도시). 실제 위치 조회(GeoIP)가 아니다.
    HOME_GEO = (37.57, 126.98, "Seoul")
    GEO = {"198.51.100.10": (35.68, 139.69, "Tokyo"), "198.51.100.20": (39.04, -77.49, "Ashburn"),
           "203.0.113.5": (50.11, 8.68, "Frankfurt"), "203.0.113.40": (1.35, 103.82, "Singapore"),
           "192.0.2.53": (37.57, 126.98, "Seoul"), "203.0.113.66": (-23.55, -46.63, "São Paulo")}
    ALERT_SAMPLES = [("LOW", "ids-alert", "ET INFO 의심 TLD 접속 (demo.example.zip)"),
                     ("MEDIUM", "dns-dga", "NXDOMAIN 급증: 5분 내 72회"),
                     ("MEDIUM", "ids-alert", "EXITGUARD 평문 HTTP Basic Auth 전송"),
                     ("HIGH", "ids-alert", "ET MALWARE 알려진 C2 비컨 패턴 (데모)")]
    ALERT_DESTS = ("198.51.100.10", "192.0.2.53", "203.0.113.40", "203.0.113.66")

    def __init__(self):
        super().__init__()
        import random
        self.rnd = random.Random(7)
        self.names = dict(self.CLIENTS); self.names["100.64.0.1"] = "demo-exit"
        self.ts_self = {"HostName": "demo-exit", "ExitNodeOption": True, "TailscaleIPs": ["100.64.0.1"]}
        self.ts_peers = {ip: {"HostName": n, "TailscaleIPs": [ip], "CurAddr": "x" if i != 2 else "", "Relay": "tok"}
                         for i, (ip, n) in enumerate(self.CLIENTS.items())}
        self.services = {s: "active" for s in ("suricata", "exitguard-watch", "exitguard-nft", "tailscaled")}
        self.stats = {"capture": {"kernel_packets": 0, "kernel_drops": 0}, "uptime": 0}
        self.totals = {ip: 0 for ip in self.CLIENTS}
        self.t0 = time.time()
        now = time.time()
        for i, (lv, kind, title) in enumerate(self.ALERT_SAMPLES):
            ts = datetime.fromtimestamp(now - (len(self.ALERT_SAMPLES) - i) * 900).isoformat(timespec="seconds")
            self.alerts.append({"ts": ts, "level": lv, "kind": kind, "title": title, "client": list(self.CLIENTS)[i % 3],
                                "dest": self.ALERT_DESTS[i],
                                "action": "목적지 24h 차단" if lv == "HIGH" else None})
        self.nft["blocked"] = {"203.0.113.66": {}}

    def read_slow(self):
        pass

    def geo(self, win=120):
        now = time.time(); agg = collections.Counter(); host = {}
        for ts, c, ext, port, proto, b, app in self.flows:
            if now - ts <= win:
                agg[ext] += b
        for ext, port, proto, app, h in self.SITES:
            host[ext] = h
        pts = [{"ip": ip, "host": host.get(ip, ""), "city": city, "lat": lat, "lon": lon, "bytes": agg.get(ip, 0),
                "blocked": ip in self.nft["blocked"], "level": "HIGH" if ip in self.nft["blocked"] else None}
               for ip, (lat, lon, city) in self.GEO.items() if agg.get(ip) or ip in self.nft["blocked"]]
        lat, lon, city = self.HOME_GEO
        return {"home": {"city": city, "lat": lat, "lon": lon}, "points": pts}

    def read_alerts(self):
        if self.rnd.random() < 0.03:
            lv, kind, title = self.rnd.choice(self.ALERT_SAMPLES[:3])
            self.alerts.append({"ts": datetime.now().isoformat(timespec="seconds"), "level": lv, "kind": kind,
                                "dest": self.ALERT_DESTS[self.ALERT_SAMPLES.index((lv, kind, title))],
                                "title": title, "client": self.rnd.choice(list(self.CLIENTS)), "action": None})
            self.alerts = self.alerts[-500:]

    def read_eve(self):
        now = time.time(); r = self.rnd
        cap = self.stats["capture"]
        cap["kernel_packets"] += r.randint(800, 2500); cap["kernel_drops"] += r.random() < 0.1
        self.stats["uptime"] = int(now - self.t0) + 3600
        for ip in self.CLIENTS:
            for _ in range(r.randint(1, 4)):
                ext, port, proto, app, host = r.choice(self.SITES)
                b = int(r.expovariate(1 / 200_000))
                self.flows.append((now, ip, ext, port, proto, b, app))
                self.dests.append((now, ip, f"{host} [{app}]"))
                self.last_seen[ip] = now
                self.totals[ip] += b

    def read_nft(self):
        self.nft["clients"] = {ip: {"counter": {"bytes": b}} for ip, b in self.totals.items()}
        self.rates = {ip: b / 2 for ip, b in self.totals.items()} if not self._prev_t else \
            {ip: max(0, b - self._prev_nft.get(ip, 0)) / 2 for ip, b in self.totals.items()}
        self._prev_nft = dict(self.totals); self._prev_t = time.time()


# ---------------------------------------------------------------- render
LEVEL_COLOR = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 3}
WIDE_W = 130     # 이 폭 이상: 2단 레이아웃 (기존 그대로)
NARROW_W = 80    # 이 폭 미만: 클라이언트 표에서 IP 열 숨김
TINY_W = 60      # 이 폭 미만: 기기명+속도+알림만, 축약 표기
# 클라이언트 표 열: (키, 머리글, 폭, 오른쪽정렬). 기기명 폭은 화면 폭에 맞춰 조정된다.
CLIENT_COLS = {"ip": ("IP", 16, False), "rate": (None, 8, True), "flows": ("플로우", 7, True), "ndest": ("목적지", 7, True),
               "alerts": ("알림", 5, True), "link": ("  링크", 12, False), "seen": ("마지막", 6, True)}


class UI:
    def __init__(self, scr, m):
        self.scr, self.m = scr, m
        self.interval = 2.0
        curses.curs_set(0); curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1); curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1); curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE); curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        self.scr.nodelay(True)

    def put(self, y, x, s, attr=0, maxw=None):
        h, w = self.scr.getmaxyx()
        if y >= h or x >= w:
            return
        maxw = w - x if maxw is None else min(maxw, w - x)
        s = clip(s, max(0, maxw - 1 if y == h - 1 else maxw))   # 글자 수가 아닌 표시 폭 기준 (한글 2칸)
        if not s:
            return
        try:
            self.scr.addstr(y, x, s, attr)
        except curses.error:
            pass

    def box(self, y, x, h, w, title):
        try:
            win = self.scr.derwin(h, w, y, x); win.box()
        except curses.error:
            return
        self.put(y, x + 2, f" {title} ", curses.A_BOLD, w - 3)

    def draw(self):
        m = self.m; scr = self.scr; scr.erase()
        H, W = scr.getmaxyx()
        # 헤더
        approved = m.ts_self.get("ExitNodeOption")
        adv = "승인됨" if approved else "미승인/미광고"
        host = m.ts_self.get('HostName', os.uname().nodename); now = datetime.now()
        hdr = f" ExitGuard  {host}  exit node: {adv}  {now:%m-%d %H:%M:%S}  refresh {self.interval:.0f}s "
        if W < WIDE_W:
            short = "승인" if approved else "미승인"
            hdr = first_fit([hdr, f" ExitGuard  {host}  exit node: {adv}  {now:%H:%M:%S} ",
                             f" ExitGuard  {host}  exit: {short}  {now:%H:%M:%S} ",
                             f" ExitGuard {host} {short} {now:%H:%M:%S}", f" {host} {short} {now:%H:%M}"], W)
        self.put(0, 0, fit(hdr, W), curses.color_pair(5) | curses.A_BOLD)
        top = self.status_line(1, W) if W < WIDE_W else self.status_wide()

        wide = W >= WIDE_W
        body_h = H - top - 1
        if wide:
            lw = W * 55 // 100; rw = W - lw
            ch = max(6, body_h * 45 // 100)
            self.panel_clients(top, 0, ch, lw)
            self.panel_dests(top + ch, 0, body_h - ch, lw)
            ah = max(6, body_h * 55 // 100)
            self.panel_alerts(top, lw, ah, rw)
            self.panel_recent(top + ah, lw, body_h - ah, rw)
        else:
            ch = min(max(5, len(m.clients()) + 3), body_h // 3)
            self.panel_clients(top, 0, ch, W)
            ah = max(5, (body_h - ch) // 2)
            self.panel_alerts(top + ch, 0, ah, W)
            self.panel_recent(top + ch + ah, 0, body_h - ch - ah, W)
        self.footer(H, W)
        scr.refresh()

    def alert_counts(self):
        day = time.time() - 86400
        return collections.Counter(a["level"] for a in self.m.alerts if datetime.fromisoformat(a["ts"]).timestamp() > day)

    def status_wide(self):
        """130칸 이상: 기존 한 줄 상태줄 그대로. 본문 시작 줄을 돌려준다."""
        m = self.m
        x = 1
        for s, short in (("suricata", "IDS"), ("exitguard-watch", "WATCH"), ("exitguard-nft", "NFT"), ("tailscaled", "TS")):
            st = m.services.get(s, "?"); ok = st == "active"
            self.put(1, x, ("● " if ok else "✖ ") + short, curses.color_pair(4 if ok else 1) | curses.A_BOLD); x += len(short) + 4
        cap = m.stats.get("capture", {}); pk = cap.get("kernel_packets", 0); dr = cap.get("kernel_drops", 0)
        pct = (dr / pk * 100) if pk else 0
        self.put(1, x, f"│ 캡처 {pk:,} pkt  드롭 {dr:,} ({pct:.2f}%)  업타임 {m.stats.get('uptime', 0)//60}m", curses.color_pair(1 if pct > 1 else 0)); x += 48
        cnt = self.alert_counts()
        s = f"│ 24h 알림  C{cnt['CRITICAL']} H{cnt['HIGH']} M{cnt['MEDIUM']} L{cnt['LOW']}"
        self.put(1, x, s, curses.color_pair(1 if cnt["CRITICAL"] + cnt["HIGH"] else 2 if cnt["MEDIUM"] else 0) | curses.A_BOLD)
        nb, nq = len(m.nft["blocked"]), len(m.nft["quar"])
        self.put(1, x + len(s) + 2, f"│ 차단 {nb}  격리 {nq}" if IS_ROOT else "│ 차단/격리: root 필요", curses.color_pair(1 if nq else 0))
        return 2

    def status_line(self, y, W):
        """130칸 미만: 상태 항목을 (긴 표기 → 짧은 표기) 후보로 만들어 한 줄에 안 들어가면 두 줄로 나눈다.
        1줄: 서비스 + 캡처/드롭,  2줄: 24h 알림 + 차단/격리. 본문 시작 줄을 돌려준다."""
        m = self.m
        svc = []
        for s, short in (("suricata", "IDS"), ("exitguard-watch", "WATCH"), ("exitguard-nft", "NFT"), ("tailscaled", "TS")):
            ok = m.services.get(s, "?") == "active"
            svc.append((("● " if ok else "✖ ") + short, curses.color_pair(4 if ok else 1) | curses.A_BOLD))
        cap = m.stats.get("capture", {}); pk = cap.get("kernel_packets", 0); dr = cap.get("kernel_drops", 0)
        pct = (dr / pk * 100) if pk else 0; up = m.stats.get('uptime', 0) // 60
        capc = [f"캡처 {pk:,} pkt  드롭 {dr:,} ({pct:.2f}%)  업타임 {up}m", f"캡처 {pk:,}  드롭 {dr:,} ({pct:.2f}%)",
                f"드롭 {pct:.2f}%", f"D{pct:.1f}%"]
        cnt = self.alert_counts()
        cc = f"C{cnt['CRITICAL']} H{cnt['HIGH']} M{cnt['MEDIUM']} L{cnt['LOW']}"
        alc = [f"24h 알림  {cc}", f"24h {cc}", cc]
        nb, nq = len(m.nft["blocked"]), len(m.nft["quar"])
        blc = [f"차단 {nb}  격리 {nq}", f"차단{nb} 격리{nq}"] if IS_ROOT else ["차단/격리: root 필요", "조치: root", "root"]
        cap_attr = curses.color_pair(1 if pct > 1 else 0)
        al_attr = curses.color_pair(1 if cnt["CRITICAL"] + cnt["HIGH"] else 2 if cnt["MEDIUM"] else 0) | curses.A_BOLD
        bl_attr = curses.color_pair(1 if nq else 0)

        def build(seps, cands):
            """[(후보들, attr)] 을 '│' 로 이어 폭 W-1 에 맞추고 [(text, attr)] 반환. 항목을 번갈아 짧은 표기로 바꾼다."""
            idx = [0] * len(cands); turn = 0
            while True:
                parts = []
                for i, (cs, attr) in enumerate(cands):
                    if i:
                        parts.append((seps, 0))
                    parts.append((cs[idx[i]], attr))
                if sum(wcwidth(t) for t, _ in parts) <= W - 1:
                    return parts
                for k in range(len(cands)):          # 항목을 돌아가며 한 단계씩 줄인다
                    i = (turn + k) % len(cands)
                    if idx[i] < len(cands[i][0]) - 1:
                        idx[i] += 1; turn = i + 1; break
                else:
                    return parts

        svc_txt = "  ".join(t for t, _ in svc)
        svc_cands = [svc_txt, " ".join(t for t, _ in svc)]
        one = build(" │ ", [(svc_cands[:1], 0), (capc[:2], cap_attr), (alc[:2], al_attr), (blc[:1], bl_attr)])
        if sum(wcwidth(t) for t, _ in one) <= W - 1:
            lines = [one]
        else:
            lines = [build(" │ ", [(svc_cands, 0), (capc, cap_attr)]), build(" │ ", [(alc, al_attr), (blc, bl_attr)])]
        for row, parts in enumerate(lines):
            x = 1
            for i, (t, attr) in enumerate(parts):
                if i == 0 and t in svc_cands:      # 서비스는 항목마다 색이 달라 따로 그린다
                    gap = 2 if t == svc_cands[0] else 1
                    for st, sattr in svc:
                        self.put(y + row, x, st, sattr); x += wcwidth(st) + gap
                    x -= gap
                    continue
                self.put(y + row, x, t, attr); x += wcwidth(t)
        return y + len(lines)

    def footer(self, H, W):
        m = self.m
        msg = f" {m.msg}" if m.msg else ""
        if W >= WIDE_W:
            foot = " q 종료  +/- 주기  " + ("b 차단  u 해제  Q 격리  R 격리해제  c pcap " if IS_ROOT else "(조치하려면 sudo 로 실행) ") + msg
        else:
            if IS_ROOT:
                cands = [" q 종료  +/- 주기  b 차단  u 해제  Q 격리  R 격리해제  c pcap ",
                         " q종료 +/-주기 b차단 u해제 Q격리 R격리해제 c pcap ",
                         " q종료 +/- b차단 u해제 Q격리 R해제 c캡처 ", " q종료 b차단 u해제 Q격리 R해제 c캡처 ", " q b u Q R c "]
            else:
                cands = [" q 종료  +/- 주기  (조치하려면 sudo 로 실행) ", " q 종료  +/- 주기  (조치: sudo) ",
                         " q 종료  +/- 주기 ", " q 종료 "]
            # 조치 결과 메시지(실패 사유 등)가 있으면 단축키 안내를 줄여서라도 메시지를 먼저 보여준다
            foot = first_fit([c + msg for c in cands], W - 1)
        self.put(H - 1, 0, fit(foot, W - 1), curses.A_REVERSE)

    def panel_clients(self, y, x, h, w):
        m = self.m
        self.box(y, x, h, w, "클라이언트 (최근 5분)")
        rate_hdr = "속도/s " if IS_ROOT else "5분량 "
        W = self.scr.getmaxyx()[1]
        if W >= WIDE_W:
            cols = list(CLIENT_COLS)
        elif W >= NARROW_W:
            cols = ["ip", "rate", "flows", "ndest", "alerts", "link", "seen"]
        elif W >= TINY_W:
            cols = ["rate", "flows", "ndest", "alerts", "link", "seen"]
        else:
            cols = ["rate", "alerts"]
        # 기기명 폭: 2단(130+)은 기존 22칸 고정, 그 외에는 남는 폭을 쓰되 10~22칸
        name_w = 22 if W >= WIDE_W else max(10, min(22, w - 2 - sum(CLIENT_COLS[c][1] for c in cols)))
        if W < TINY_W:
            name_w = max(10, w - 2 - sum(CLIENT_COLS[c][1] for c in cols))
        hdr = fit("기기", name_w)
        for c in cols:
            title, cw, right = CLIENT_COLS[c]
            title = rate_hdr if c == "rate" else title
            hdr += "  " + fit(title.strip(), cw - 2) if c == "link" else fit(title, cw, right)
        self.put(y + 1, x + 1, hdr, curses.A_UNDERLINE, w - 2)
        rows = m.clients()
        if not rows:
            self.put(y + 2, x + 2, "아직 이 exit node 를 지나는 트래픽이 없습니다.", curses.color_pair(3), w - 3)
        for i, r in enumerate(rows[: h - 3]):
            rate = human(r["rate"]) if r["rate"] is not None else human(r["bytes"])
            flag = " ⛔" if r["quar"] else ""
            attr = curses.color_pair(1) | curses.A_BOLD if r["quar"] else (curses.color_pair(2) if r["alerts"] else 0)
            val = {"ip": fit(r['ip'], 16), "rate": f"{rate:>8}", "flows": f"{r['flows']:>7}", "ndest": f"{r['ndest']:>7}",
                   "alerts": f"{r['alerts']:>5}", "link": "  " + fit(r['link'], 10),
                   "seen": fit(ago(r['seen']) if r['seen'] else '-', 6, True)}
            line = fit(r['name'] + flag, name_w) + "".join(val[c] for c in cols)
            self.put(y + 2 + i, x + 1, line, attr, w - 2)

    def panel_dests(self, y, x, h, w):
        m = self.m
        self.box(y, x, h, w, "상위 목적지 (최근 2분, 바이트)")
        for i, (k, b, c) in enumerate(m.top_dests(n=h - 2)):
            self.put(y + 1 + i, x + 1, f"{human(b):>8}  {k:<40} ← " + m.name(c), 0, w - 2)

    def panel_alerts(self, y, x, h, w):
        m = self.m
        self.box(y, x, h, w, "알림 (최신순)")
        rows = [a for a in m.alerts if a.get("level") != "INFO"][::-1][: h - 2]
        if not rows:
            self.put(y + 1, x + 2, "알림 없음", curses.color_pair(4), w - 3)
        for i, a in enumerate(rows):
            t = a["ts"][11:19]; lv = a["level"]
            act = " ⛔" if a.get("action") and "실패" not in a["action"] else ""
            if self.scr.getmaxyx()[1] >= WIDE_W:
                line = f"{t} {lv[:4]:<4} " + fit(m.name(a.get('client') or '-'), 14) + f" {a['title'][:w - 40]}{act}"
            elif w < TINY_W:     # 좁은 화면: HH:MM, 등급 한 글자, 기기 10칸, 제목은 남는 폭 전부 (⛔ 는 앞에)
                line = f"{t[:5]} {lv[:1]} " + fit(m.name(a.get('client') or '-'), 10) + f"{act} {a['title']}"
            else:                # 제목을 글자 수가 아닌 표시 폭으로 자르고 ⛔ 표시는 남긴다
                head = f"{t} {lv[:4]:<4} " + fit(m.name(a.get('client') or '-'), 14) + " "
                line = head + clip(a['title'], max(0, w - 2 - wcwidth(head) - wcwidth(act))) + act
            self.put(y + 1 + i, x + 1, line, curses.color_pair(LEVEL_COLOR.get(lv, 0)) | (curses.A_BOLD if lv in ("HIGH", "CRITICAL") else 0), w - 2)

    def panel_recent(self, y, x, h, w):
        m = self.m
        self.box(y, x, h, w, "실시간 접속지 (SNI / DNS / HTTP)")
        for i, (ts, c, label) in enumerate(m.recent_dests(h - 2)):
            nw = 14 if w >= TINY_W else 10
            self.put(y + 1 + i, x + 1, f"{datetime.fromtimestamp(ts):%H:%M:%S} " + fit(m.name(c), nw) + f" {label}", 0, w - 2)

    def prompt(self, text):
        H, W = self.scr.getmaxyx()
        curses.echo(); curses.curs_set(1); self.scr.nodelay(False)
        self.put(H - 1, 0, (" " + text).ljust(W - 1), curses.A_REVERSE); self.scr.refresh()
        try:
            s = self.scr.getstr(H - 1, len(text) + 2, 60).decode().strip()
        except Exception:
            s = ""
        curses.noecho(); curses.curs_set(0); self.scr.nodelay(True)
        return s

    def action(self, key):
        m = self.m
        fam = lambda ip: "6" if ":" in ip else "4"
        if key == "b":
            ip = self.prompt("차단할 외부 IP [시간, 기본 24]:")
            if ip:
                p = ip.split(); hrs = int(p[1]) if len(p) > 1 else 24
                r = subprocess.run(["nft", "add", "element", "inet", "exitguard", f"blocked{fam(p[0])}", f"{{ {p[0]} timeout {hrs*3600}s }}"], capture_output=True, text=True)
                m.msg = f"차단 {p[0]} {hrs}h" if r.returncode == 0 else f"실패: {r.stderr.strip()[:50]}"
        elif key == "u":
            ip = self.prompt("차단 해제할 IP:")
            if ip:
                r = subprocess.run(["nft", "delete", "element", "inet", "exitguard", f"blocked{fam(ip)}", f"{{ {ip} }}"], capture_output=True, text=True)
                m.msg = f"해제 {ip}" if r.returncode == 0 else f"실패: {r.stderr.strip()[:50]}"
        elif key == "Q":
            ip = self.prompt("격리할 클라이언트 IP [시간, 기본 1]:")
            if ip:
                p = ip.split(); hrs = int(p[1]) if len(p) > 1 else 1
                r = subprocess.run(["nft", "add", "element", "inet", "exitguard", f"quarantine{fam(p[0])}", f"{{ {p[0]} timeout {hrs*3600}s }}"], capture_output=True, text=True)
                m.msg = f"격리 {p[0]} {hrs}h" if r.returncode == 0 else f"실패: {r.stderr.strip()[:50]}"
        elif key == "R":
            ip = self.prompt("격리 해제할 클라이언트 IP:")
            if ip:
                r = subprocess.run(["nft", "delete", "element", "inet", "exitguard", f"quarantine{fam(ip)}", f"{{ {ip} }}"], capture_output=True, text=True)
                m.msg = f"격리 해제 {ip}" if r.returncode == 0 else f"실패: {r.stderr.strip()[:50]}"
        elif key == "c":
            ip = self.prompt("pcap 캡처할 클라이언트 IP [초, 기본 60]:")
            if ip:
                p = ip.split(); sec = p[1] if len(p) > 1 else "60"
                subprocess.Popen(["exitguardctl", "capture", p[0], sec], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                m.msg = f"{p[0]} 캡처 {sec}초 시작 → /var/log/exitguard/pcap/"

    def loop(self):
        last = 0
        while True:
            if time.time() - last >= self.interval:
                self.m.refresh(); self.draw(); last = time.time()
            try:
                k = self.scr.getkey()
            except curses.error:
                time.sleep(0.1); continue
            if k in ("q", "Q") and not (k == "Q" and IS_ROOT):
                return
            if k == "KEY_RESIZE":
                self.draw()
            elif k == "+":
                self.interval = min(30, self.interval + 1); last = 0
            elif k == "-":
                self.interval = max(1, self.interval - 1); last = 0
            elif k in ("b", "u", "Q", "R", "c") and IS_ROOT:
                self.action(k); last = 0
            elif k == "r":
                last = 0


def text_snapshot(m):
    m.refresh(); time.sleep(0.2); m.refresh()
    cap = m.stats.get("capture", {})
    print(f"ExitGuard @ {datetime.now():%Y-%m-%d %H:%M:%S}  exit node: {'승인됨' if m.ts_self.get('ExitNodeOption') else '미승인'}")
    print("서비스: " + "  ".join(f"{s}={st}" for s, st in m.services.items()))
    print(f"캡처: {cap.get('kernel_packets', 0):,} pkt, 드롭 {cap.get('kernel_drops', 0):,}")
    print("\n클라이언트 (최근 5분)")
    for r in m.clients():
        print(f"  {r['name']:<22}{r['ip']:<16}{human(r['bytes']):>8}  flows={r['flows']:<5} dests={r['ndest']:<4} alerts={r['alerts']:<3} {r['link']}")
    print("\n상위 목적지 (2분)")
    for k, b, c in m.top_dests(n=10):
        print(f"  {human(b):>8}  {k:<40} ← {m.name(c)}")
    print("\n최근 알림")
    for a in m.alerts[-8:][::-1]:
        print(f"  {a['ts'][11:19]} {a['level']:<8} {m.name(a.get('client') or '-'):<16} {a['title']}  {a.get('action') or ''}")
    print("\n실시간 접속지")
    for ts, c, label in m.recent_dests(10):
        print(f"  {datetime.fromtimestamp(ts):%H:%M:%S} {m.name(c):<16} {label}")


# ---------------------------------------------------------------- web (읽기 전용)
# 같은 Model 을 브라우저로 보여준다. 조치(차단·격리·pcap) 경로는 일부러 두지 않는다: GET 두 개만 처리.

LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def alert_groups(m, since, n=20):
    """같은 (등급, 제목) 알림을 한 줄로 접는다: 횟수·최근 시각·관련 기기. 등급 높은 것, 최근 것 순."""
    groups = {}
    for a in m.alerts:
        lv = a.get("level")
        if lv == "INFO":
            continue
        try:
            if datetime.fromisoformat(a["ts"]).timestamp() <= since:
                continue
        except Exception:
            continue
        g = groups.setdefault((lv, a.get("title")), {"level": lv, "kind": a.get("kind"), "title": a.get("title"),
                                                    "count": 0, "last": "", "clients": [], "action": None})
        g["count"] += 1
        if a["ts"] >= g["last"]:
            g["last"] = a["ts"]; g["action"] = a.get("action") or g["action"]
        name = m.name(a.get("client") or "-")
        if name not in g["clients"]:
            g["clients"].append(name)
    out = sorted(groups.values(), key=lambda g: g["last"], reverse=True)
    out.sort(key=lambda g: LEVEL_RANK.get(g["level"], 9))
    return out[:n]


def slack_status():
    """Configuration metadata only; never expose webhook URLs or claim delivery."""
    if DEMO:
        return {"state": "demo", "min_level": "MEDIUM"}
    try:
        with open(CFG_PATH) as f:
            notify = json.load(f).get("notify", {})
        url = notify.get("webhook_url") or ""
        parsed = urlsplit(url)
        slack = (parsed.scheme == "https" and parsed.hostname in ("hooks.slack.com", "hooks.slack-gov.com")
                 and parsed.path.startswith("/services/") and not parsed.username and not parsed.password)
        level = notify.get("min_level", "MEDIUM")
        return {"state": "configured" if slack else "other" if url else "missing",
                "min_level": level if level in LEVEL_RANK else "UNKNOWN"}
    except (OSError, ValueError, TypeError, AttributeError):
        return {"state": "unknown", "min_level": "UNKNOWN"}


def snapshot(m):
    """Model 상태를 JSON 직렬화 가능한 dict 로. 웹 대시보드 /api/snapshot 응답."""
    now = time.time(); day = now - 86400
    cap = m.stats.get("capture", {}); pk = cap.get("kernel_packets", 0); dr = cap.get("kernel_drops", 0)
    cnt = collections.Counter()
    latest = {}
    for a in m.alerts:
        try:
            timestamp = datetime.fromisoformat(a["ts"]).timestamp()
            if timestamp > day:
                cnt[a.get("level")] += 1
            dest = a.get("dest")
            if dest and timestamp > latest.get(dest, (float("-inf"), None))[0]:
                latest[dest] = (timestamp, a)
        except Exception:
            pass
    geo = m.geo()
    geo = {"home": geo.get("home"), "points": [dict(p) for p in geo.get("points", [])]}
    for p in geo["points"]:
        alert = latest.get(p["ip"], (None, None))[1]
        p["last_alert"] = ({k: alert.get(k) for k in ("ts", "level", "title")} if alert else None)
    return {
        "generated": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
        "demo": DEMO,
        "slack": slack_status(),
        "host": m.ts_self.get("HostName") or os.uname().nodename,
        "exit_node_approved": bool(m.ts_self.get("ExitNodeOption")),
        "services": dict(m.services),
        "capture": {"packets": pk, "drops": dr, "drop_pct": round(dr / pk * 100, 2) if pk else 0,
                    "uptime_s": m.stats.get("uptime", 0)},
        "alerts_24h": {lv: cnt[lv] for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "nft_visible": IS_ROOT or DEMO,
        "blocked": len(m.nft["blocked"]), "quarantined": len(m.nft["quar"]),
        "clients": [{"name": r["name"], "ip": r["ip"], "bytes_5m": r["bytes"], "rate": r["rate"],
                     "rate_h": human(r["rate"]).strip() + "/s" if r["rate"] is not None else None,
                     "bytes_5m_h": human(r["bytes"]).strip(), "flows": r["flows"], "dests": r["ndest"],
                     "alerts": r["alerts"], "link": r["link"], "quarantined": r["quar"],
                     "last_seen": r["seen"], "ago": ago(r["seen"]) if r["seen"] else None}
                    for r in m.clients()],
        "top_dests": [{"dest": k, "bytes": b, "bytes_h": human(b).strip(), "client": c, "client_name": m.name(c)}
                      for k, b, c in m.top_dests(n=10)],
        "alerts": [{"ts": a.get("ts"), "level": a.get("level"), "kind": a.get("kind"), "title": a.get("title"),
                    "dest": a.get("dest"),
                    "client": a.get("client"), "client_name": m.name(a.get("client") or "-"), "action": a.get("action")}
                   for a in [a for a in m.alerts if a.get("level") != "INFO"][-30:][::-1]],
        "alert_groups": alert_groups(m, day),
        "series": m.series(),
        "protos": m.protos(),
        "geo": geo,
        "recent": [{"ts": datetime.fromtimestamp(ts).isoformat(timespec="seconds"), "client": c,
                    "client_name": m.name(c), "label": label}
                   for ts, c, label in m.recent_dests(30)],
    }


WEB_HTML = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ExitGuard</title>
<style>
:root{color-scheme:dark;--bg:#080f1a;--card:#101c2b;--fg:#e6edf3;--mute:#9babbe;--line:#26364a;--ok:#49dba0;--bad:#ff717b;--warn:#eeb45b;--info:#65b7ff;--hdr:#101c2b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
header{background:var(--hdr);color:#fff;padding:18px 24px;display:flex;flex-wrap:wrap;gap:6px 16px;align-items:baseline;border-bottom:1px solid var(--line)}
header h1{font-size:17px;margin:0}
header .sub{opacity:.85;font-size:13px}
.badge{display:inline-block;font-size:11px;padding:1px 6px;border-radius:9px;background:#ffffff30;margin-left:4px}
main{padding:clamp(10px,1.5vw,28px);display:grid;gap:clamp(12px,1.2vw,24px);grid-template-columns:minmax(0,1fr);grid-template-areas:"summary" "globe" "recent" "alerts" "clients" "dests" "protocols" "status" "slack";max-width:2400px;margin:0 auto}
.summary{grid-area:summary}.globe-panel{grid-area:globe}.recent-panel{grid-area:recent}.alerts-panel{grid-area:alerts}.clients-panel{grid-area:clients}.dests-panel{grid-area:dests}.protocols-panel{grid-area:protocols}.status-panel{grid-area:status}.slack-panel{grid-area:slack}
@media(min-width:760px){main{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-areas:"summary summary" "globe globe" "recent alerts" "clients clients" "dests protocols" "status status" "slack slack"}}
@media(min-width:1200px){main{grid-template-columns:minmax(0,1.55fr) minmax(360px,1fr);grid-template-areas:"summary summary" "globe recent" "globe alerts" "clients clients" "dests protocols" "status status" "slack slack"}.globe-panel{display:flex;flex-direction:column;justify-content:center}.globe-panel h2{align-self:stretch}#recent{max-height:220px}#alerts{max-height:260px;overflow:auto}.clients-panel #clients{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.clients-panel #clients .row{border-top:0}.clients-panel #traffic{max-width:1200px;margin:auto}}
header>*{min-width:0;overflow-wrap:anywhere}section,p,.metric{overflow-wrap:anywhere}main>*{min-width:0}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;min-width:0}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.metric{padding:18px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.metric span{display:block;color:var(--mute);font-size:12px}.metric strong{display:block;font-size:32px;font-variant-numeric:tabular-nums;margin-top:8px}
.metric:nth-child(3) strong,.metric:nth-child(4) strong{color:var(--bad)}
.globe-panel{background:radial-gradient(ellipse at center,#142b45,var(--card) 75%);text-align:center}
.globe-panel h2{text-align:left}#globe{width:100%;max-width:980px;margin:auto;max-height:75vh;min-height:220px}
#traffic{margin-top:12px}#donut{max-width:600px;margin:auto}
.service{flex:1 1 150px;padding:10px 12px;border-left:4px solid currentColor;background:#080f1a;border-radius:4px}
.status-detail{flex-basis:100%;font-size:12px}
.slack-guide summary{cursor:pointer;display:inline-block;padding:8px 12px;border:1px solid var(--line);border-radius:6px;color:var(--fg)}
.slack-guide li{margin:8px 0}.slack-guide code{overflow-wrap:anywhere}
#recent{max-height:300px;overflow:auto}.fresh{animation:arrival .65s ease-out}
#recent,#alerts{scrollbar-gutter:stable}
@keyframes arrival{from{transform:translateY(-12px);background:#1d4357}to{transform:translateY(0);background:transparent}}
@media(max-width:600px){main{padding:12px 10px;gap:12px}.summary{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.metric{padding:12px}.metric strong{font-size:28px}header{padding:14px}.globe-panel{padding:10px 4px}}
@media(prefers-reduced-motion:reduce){.fresh{animation:none}}
h2{font-size:13px;margin:0 0 8px;color:var(--mute);font-weight:600;text-transform:none}
.stat{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:13px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.info{color:var(--info)}.mute{color:var(--mute)}
.row{border-top:1px solid var(--line);padding:7px 0;display:flex;flex-wrap:wrap;gap:2px 10px;align-items:baseline}
.row:first-of-type{border-top:0}
.row .main{flex:1 1 100%;font-weight:600;word-break:break-all}
.row .k{font-size:12px;color:var(--mute)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
.lv{font-size:11px;font-weight:700;padding:0 5px;border-radius:4px;border:1px solid currentColor}
.empty{color:var(--mute);padding:6px 0}
.chart{width:100%;height:auto;display:block}
.eg-alert{display:flex;gap:8px;align-items:center;border-top:1px solid var(--line);padding:10px 0}
.eg-lv{font-size:10px;font-weight:700;color:#fff;border-radius:4px;padding:2px 5px;min-width:58px;text-align:center}
.eg-body{flex:1;min-width:0}.eg-title{font-weight:600;overflow-wrap:anywhere}
.eg-meta{font-size:12px;color:var(--mute);overflow-wrap:anywhere}.eg-count{font-weight:700}
footer{color:var(--mute);font-size:12px;text-align:center;padding:4px 16px 20px}
</style></head><body>
<header><h1>ExitGuard<span id="demo" class="badge" hidden>DEMO</span></h1>
<span class="sub" id="host">…</span><span class="sub" id="when"></span></header>
<main>
<div class="summary wide" aria-label="네트워크 요약">
<div class="metric"><span>연결 기기</span><strong id="count-clients">—</strong></div>
<div class="metric"><span>목적지</span><strong id="count-dests">—</strong></div>
<div class="metric"><span>차단</span><strong id="count-blocked">—</strong></div>
<div class="metric"><span>위험 알림 · 24h</span><strong id="count-risk">—</strong></div>
</div>
<section class="wide globe-panel"><h2>목적지 지구본 · NETWORK ACTIVITY</h2><svg id="globe" class="chart" aria-label="트래픽 목적지 지구본"></svg><p id="geo-empty" class="empty">위치 정보 없음</p><p class="mute">드래그 회전 · 휠/핀치 확대 · 더블클릭 원위치</p></section>
<section class="recent-panel"><h2>실시간 접속지 · 최신순 · SNI / DNS / HTTP</h2><div id="recent" tabindex="0" role="region" aria-label="실시간 접속 목록"></div></section>
<section class="status-panel"><h2>상태</h2><div class="stat" id="status"></div></section>
<section class="slack-panel"><h2>Slack 이상징후 알림</h2><p id="slack-status" role="status"></p>
<details class="slack-guide"><summary>Slack 설정 안내</summary>
<ol><li>Slack에서 알림을 받을 채널용 Incoming Webhook을 만드세요. 워크스페이스 관리자 승인이 필요할 수 있습니다.</li>
<li>서버의 <code>/etc/exitguard/config.json</code> (또는 <code>EXITGUARD_CONFIG</code> 지정 파일)에서 기존 설정을 유지한 채 <code>notify.webhook_url</code>에 webhook을 저장하세요. 주소는 비밀 값입니다. 채팅·브라우저·Git에 붙여 넣지 말고 서버의 보안 편집 경로를 사용하세요.</li>
<li><code>notify.min_level</code>로 전송 기준을 선택하세요. 기본 MEDIUM 이상이며 HIGH로 올리면 높은 위험만 전송합니다. <code>notify.dedupe_sec</code>의 기본값은 600초입니다. 동일 알림이 반복되는 동안 중복 발송을 억제합니다.</li>
<li>파일 접근 권한을 제한하고 <code>sudo systemctl restart exitguard-watch</code>로 감시 서비스를 재시작하세요. 설정됨 표시는 파일 설정만 확인하며, 서비스의 적용 여부나 전송 성공을 보장하지 않습니다.</li></ol>
<p>알림에는 기기·목적지 IP, 이벤트 제목 및 상세 정보가 포함될 수 있고 Slack으로 전송됩니다. 채널 접근 권한과 외부 전송 정책을 먼저 확인하세요.</p>
<p>이 화면은 설정을 저장하거나 메시지를 보내지 않습니다. 알림은 감시 서비스가 전송하므로 브라우저를 닫아도 동작합니다. 실제 수신 여부는 Slack 채널에서 확인하세요.</p>
</details></section>
<section class="clients-panel"><h2>클라이언트 (최근 5분)</h2><div id="clients"></div><h2>기기별 트래픽 · 최근 10분</h2><svg id="traffic" class="chart" aria-label="기기별 트래픽 추이"></svg></section>
<section class="alerts-panel"><h2>24시간 등급별 알림</h2><svg id="bars" class="chart" aria-label="등급별 알림 수"></svg><h2>알림 묶음 (최신순)</h2><div id="alerts" tabindex="0" role="region" aria-label="알림 묶음 목록"></div></section>
<section class="dests-panel"><h2>상위 목적지 (최근 2분, 바이트)</h2><div id="dests"></div></section>
<section class="protocols-panel"><h2>프로토콜 비율 · 최근 5분</h2><svg id="donut" class="chart" aria-label="프로토콜별 트래픽 비율"></svg></section>
</main>
<footer>읽기 전용 · 2초마다 갱신 · <span id="err"></span></footer>
<script src="static/viz.js"></script>
<script>
"use strict";
const $ = id => document.getElementById(id);
let globe = null, latestGeo = null, centered = false;
let recentKeys = null, mapFailed = false;
function updateGlobe(){
  if(!latestGeo) return;
  $("geo-empty").hidden = !mapFailed && !!(latestGeo.home && latestGeo.points && latestGeo.points.length);
  if(!globe) return;
  globe.update(latestGeo);
  if(!centered){globe.center(); centered = true;}
}
fetch("static/countries-110m.json").then(r => {
  if(!r.ok) throw new Error("지도 로드 실패");
  return r.json();
}).then(topo => {
  globe = EGViz.globe($("globe"), topo, {width:600, height:520});
  updateGlobe();
}).catch(() => {mapFailed = true; $("geo-empty").hidden = false; $("geo-empty").textContent = "지도를 불러올 수 없습니다.";});
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!=null) e.textContent=String(text); return e;}
const LV = {CRITICAL:"bad",HIGH:"bad",MEDIUM:"warn",LOW:"info",INFO:"mute"};
function fill(box, items, render, emptyText){
  box.replaceChildren();
  if(!items.length){box.append(el("div","empty",emptyText)); return;}
  for(const it of items) box.append(render(it));
}
function hms(iso){return iso ? String(iso).slice(11,19) : "";}
function render(s){
  const slack = s.slack || {state:"unknown", min_level:"UNKNOWN"};
  const slackLabels = {demo:"데모 · Slack 발송 안 함", configured:"Slack webhook 설정됨 · 전송 성공 미확인", missing:"미설정", other:"다른 webhook 설정됨 · Slack 미확인", unknown:"설정 확인 불가 · 파일 또는 접근 권한 확인"};
  $("slack-status").textContent = (slackLabels[slack.state] || slackLabels.unknown) + " · 알림 기준: " + slack.min_level;
  latestGeo = s.geo || {home:null, points:[]};
  updateGlobe();
  $("count-clients").textContent = s.clients.length.toLocaleString();
  $("count-dests").textContent = (latestGeo.points || []).length.toLocaleString();
  $("count-blocked").textContent = s.blocked.toLocaleString();
  $("count-risk").textContent = (s.alerts_24h.CRITICAL + s.alerts_24h.HIGH).toLocaleString();
  $("demo").hidden = !s.demo;
  $("host").textContent = s.host + " · exit node: " + (s.exit_node_approved ? "승인됨" : "미승인/미광고");
  $("when").textContent = hms(s.generated);
  const st = $("status"); st.replaceChildren();
  for(const [name, v] of Object.entries(s.services)){
    st.append(el("span", "service " + (v==="active" ? "ok" : "bad"), (v==="active" ? "● " : "✖ ") + name + " · " + v));
  }
  const c = s.capture;
  st.append(el("span", "status-detail " + (c.drop_pct > 1 ? "bad" : "mute"), "캡처 " + c.packets.toLocaleString() + " pkt · 드롭 " + c.drops.toLocaleString() + " (" + c.drop_pct.toFixed(2) + "%)"));
  const a = s.alerts_24h;
  st.append(el("span", (a.CRITICAL + a.HIGH) ? "bad" : a.MEDIUM ? "warn" : "", "24h 알림 C" + a.CRITICAL + " H" + a.HIGH + " M" + a.MEDIUM + " L" + a.LOW));
  st.append(el("span", s.quarantined ? "bad" : "", s.nft_visible ? ("차단 " + s.blocked + " · 격리 " + s.quarantined) : "차단/격리: root 필요"));

  fill($("clients"), s.clients, r => {
    const d = el("div","row" + (r.quarantined ? " bad" : r.alerts ? " warn" : ""));
    d.append(el("div","main", r.name + (r.quarantined ? " ⛔ 격리" : "")));
    d.append(el("span","mono", r.ip));
    d.append(el("span","k", r.rate_h ? "속도 " + r.rate_h : "5분 " + r.bytes_5m_h));
    d.append(el("span","k", "플로우 " + r.flows + " · 목적지 " + r.dests + " · 알림 " + r.alerts));
    d.append(el("span","k", r.link + " · " + (r.ago || "-")));
    return d;
  }, "아직 이 exit node 를 지나는 트래픽이 없습니다.");

  EGViz.levelBars($("bars"), s.alerts_24h);
  EGViz.line($("traffic"), s.series);
  EGViz.donut($("donut"), s.protos);
  EGViz.alertGroups($("alerts"), s.alert_groups);

  fill($("dests"), s.top_dests, x => {
    const d = el("div","row");
    d.append(el("div","main mono", x.dest));
    d.append(el("span","k", x.bytes_h + " ← " + x.client_name));
    return d;
  }, "최근 2분 트래픽 없음");

  const ordered = [...s.recent].sort((a,b) => String(b.ts).localeCompare(String(a.ts)));
  const key = x => JSON.stringify([x.ts, x.client, x.label]);
  fill($("recent"), ordered, x => {
    const d = el("div","row" + (recentKeys && !recentKeys.has(key(x)) ? " fresh" : ""));
    d.append(el("span","k", hms(x.ts) + " · " + x.client_name));
    d.append(el("div","main mono", x.label));
    return d;
  }, "아직 없음");
  recentKeys = new Set(ordered.map(key));
}
async function tick(){
  try{
    const r = await fetch("api/snapshot", {cache:"no-store"});
    if(!r.ok) throw new Error("HTTP " + r.status);
    render(await r.json()); $("err").textContent = "";
  }catch(e){ $("err").textContent = "연결 오류: " + e.message; }
  finally{ setTimeout(tick, 2000); }
}
tick();
</script></body></html>
"""


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
    page = WEB_HTML.encode()

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
    print(f"ExitGuard web (읽기 전용): http://{h if ':' not in h else '[' + h + ']'}:{p}/" + ("  [demo]" if DEMO else ""), flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("주의: 루프백 외 주소에 바인딩됨. 인증이 없으므로 신뢰할 수 있는 네트워크/경로(Tailscale serve 등)에서만 쓰세요.", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


def main():
    m = DemoModel() if DEMO else Model()
    if "--web" in sys.argv:
        serve_web(m); return
    if "--text" in sys.argv:
        text_snapshot(m); return
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(lambda scr: UI(scr, m).loop())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:   # Ctrl+C 도 q 처럼 조용히 종료
        pass
