"""ExitGuard 공용 데이터 엔진: 설정, 수집(Model / DemoModel), 집계(snapshot).
텍스트판(tui.py)과 웹판(web.py)이 함께 쓴다. 화면 코드는 여기 두지 않는다.
"""
import collections, ipaddress, json, os, subprocess, sys, time, unicodedata
from datetime import datetime
from urllib.parse import urlsplit

import geoip, ids_health, purpose, slack_connect

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


def printable(s):
    """네트워크에서 온 문자열(SNI·DNS·HTTP·알림 제목)의 제어문자를 지운다.
    NUL(Suricata QUIC SNI 패딩 등)은 버리고, 나머지 제어문자·방향 전환 문자는 '?' 로. 터미널 이스케이프 주입과 curses NUL 오류 방지."""
    s = str(s).replace("\x00", "")
    return "".join("?" if unicodedata.category(ch) == "Cc" or "\u202a" <= ch <= "\u202e" or "\u2066" <= ch <= "\u2069"
                   else ch for ch in s)


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
        self.hosts = collections.OrderedDict()          # 목적지 IP -> 최근 SNI/HTTP 호스트 (지구본 툴팁)
        self._geo = {"db": None, "home": None, "mtime": None, "checked": 0, "cache": {}}

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
                    self.dests.append((ts, client, printable(f"{sni} [{t}]")))
                    self._host(ext, sni)
            elif t == "http":
                h = ev.get("http", {})
                self.dests.append((ts, client, printable(f"{h.get('hostname','?')}{(h.get('url') or '')[:30]} [http]")))
                if h.get("hostname"):
                    self._host(ext, h["hostname"])
            elif t == "dns":
                d = ev.get("dns", {})
                if d.get("type") in ("query", "request"):
                    name = d.get("rrname") or ((d.get("queries") or [{}])[0].get("rrname"))
                    if name:
                        self.dests.append((ts, client, printable(f"{name} [dns]")))

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
                        a = json.loads(line)
                        if isinstance(a.get("title"), str):
                            a["title"] = printable(a["title"])
                        self.alerts.append(a)
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

    def _host(self, ip, name):
        name = printable(name)
        if len(name) > 80:                       # 긴 이름은 뒷부분(도메인)을 남겨야 용도 표와 맞는다
            name = "…" + name[-79:]
        self.hosts[ip] = name; self.hosts.move_to_end(ip)
        if len(self.hosts) > 2000:
            self.hosts.popitem(last=False)

    def _geodb(self):
        """geo.json 과 GeoIP 파일을 1분마다 확인해 바뀌면 다시 읽는다. 파일이 없거나 깨졌으면 None (오류 아님)."""
        g = self._geo
        if time.time() - g["checked"] < 60:
            return g["db"]
        g["checked"] = time.time()
        cfg = geoip.load_settings(); g["home"] = cfg["home"]
        try:
            mtime = os.stat(cfg["db"]).st_mtime
        except OSError:
            g["db"] = None; g["mtime"] = None
            return None
        if (cfg["db"], mtime) != g["mtime"]:
            try:
                g["db"] = geoip.GeoDB(cfg["db"])
            except (OSError, ValueError, EOFError):
                g["db"] = None
            g["mtime"] = (cfg["db"], mtime); g["cache"] = {}
        return g["db"]

    def geo(self, win=120, n=60):
        """목적지 좌표 = 오프라인 GeoIP 의 국가 중심 (실제 위치 아님). 트래픽 상위 n 개 + 차단 목적지.
        GeoIP 파일이 없으면 비어 있다. home 은 geo.json 에 적은 값만 쓴다 (기본값 없음)."""
        db = self._geodb()
        if db is None:
            return {"home": None, "points": []}
        now = time.time(); agg = collections.Counter()
        for ts, c, ext, port, proto, b, app in self.flows:
            if now - ts <= win:
                agg[ext] += b
        cache = self._geo["cache"]
        if len(cache) > 20000:
            cache.clear()
        pts = []
        for ip in [ip for ip, _ in agg.most_common(n)] + [ip for ip in self.nft["blocked"] if ip not in agg]:
            if ip not in cache:
                cache[ip] = db.country(ip)
            cc = cache[ip]
            if cc not in geoip.COUNTRY:
                continue
            lat, lon, name = geoip.COUNTRY[cc]
            pts.append({"ip": ip, "host": self.hosts.get(ip, ""), "city": name, "country": cc, "lat": lat, "lon": lon,
                        "bytes": agg.get(ip, 0), "blocked": ip in self.nft["blocked"],
                        "level": "HIGH" if ip in self.nft["blocked"] else None})
        return {"home": self._geo["home"], "points": pts, "source": geoip.ATTRIBUTION}

    def country_of(self, ip):
        """목적지 IP → 나라 이름 (오프라인 GeoIP). 모르면 None. 지금 흐름이 없는 과거 알림 목적지에도 쓴다."""
        db = self._geodb()
        if db is None or not ip:
            return None
        cache = self._geo["cache"]
        if ip not in cache:
            try:
                cache[ip] = db.country(ip)
            except (ValueError, TypeError):
                cache[ip] = None
        return (geoip.COUNTRY.get(cache[ip]) or (None, None, None))[2]

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
    ALERT_DETAILS = ({"category": "Misc activity", "severity": 3, "proto": "TCP", "port": 443, "sni": "demo.example.zip"},
                     {"zone": "example.net", "queries_5min": 72},
                     {"category": "Potential Corporate Privacy Violation", "severity": 2, "proto": "TCP", "port": 80,
                      "http": "GET update.example.com/admin"},
                     {"category": "A Network Trojan was detected", "severity": 1, "proto": "TCP", "port": 443,
                      "sni": "c2.example.org"})

    def __init__(self):
        super().__init__()
        import random
        self.rnd = random.Random(7)
        self.names = dict(self.CLIENTS); self.names["100.64.0.1"] = "demo-exit"
        self.ts_self = {"HostName": "demo-exit", "ExitNodeOption": True, "TailscaleIPs": ["100.64.0.1"]}
        self.ts_peers = {ip: {"HostName": n, "TailscaleIPs": [ip], "CurAddr": "x" if i != 2 else "", "Relay": "tok"}
                         for i, (ip, n) in enumerate(self.CLIENTS.items())}
        self.services = {s: "active" for s in ("suricata", "exitguard-watch", "exitguard-nft", "tailscaled")}
        self.stats = {"capture": {"kernel_packets": 0, "kernel_drops": 0}, "uptime": 0,
                      "detect": {"engines": [{"last_reload": datetime.fromtimestamp(time.time() - 3600).isoformat(),
                                              "rules_loaded": 53363, "rules_failed": 0}]}}
        self.totals = {ip: 0 for ip in self.CLIENTS}
        self.t0 = time.time()
        now = time.time()
        for i, (lv, kind, title) in enumerate(self.ALERT_SAMPLES):
            ts = datetime.fromtimestamp(now - (len(self.ALERT_SAMPLES) - i) * 900).isoformat(timespec="seconds")
            self.alerts.append({"ts": ts, "level": lv, "kind": kind, "title": title, "client": list(self.CLIENTS)[i % 3],
                                "dest": self.ALERT_DESTS[i], "details": self.ALERT_DETAILS[i],
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

    def country_of(self, ip):
        return (self.GEO.get(ip) or (None, None, None))[2]

    def read_alerts(self):
        if self.rnd.random() < 0.03:
            i = self.rnd.randrange(3); lv, kind, title = self.ALERT_SAMPLES[i]
            self.alerts.append({"ts": datetime.now().isoformat(timespec="seconds"), "level": lv, "kind": kind,
                                "dest": self.ALERT_DESTS[i], "details": self.ALERT_DETAILS[i],
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


# ---------------------------------------------------------------- 집계 (웹 /api/snapshot, 두 화면 공용)
LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# 시그니처 이름 앞부분 → 쉬운 설명 (ET Open 규칙 분류). 위에서부터 처음 맞는 것.
EXPLAIN = [
    ("EXITGUARD HTTP Basic Auth", "암호화되지 않은 HTTP 로 아이디·비밀번호를 보냈습니다. 같은 경로의 누구나 볼 수 있으니 HTTPS 로 바꾸거나 비밀번호를 바꾸세요."),
    ("EXITGUARD", "ExitGuard 가 직접 넣은 규칙(local.rules)에 걸렸습니다."),
    ("ET MALWARE", "알려진 악성코드 통신 패턴입니다. 해당 기기를 점검하세요."),
    ("ET TROJAN", "알려진 악성코드 통신 패턴입니다. 해당 기기를 점검하세요."),
    ("ET CNC", "악성코드 지휘 서버로 알려진 곳과의 통신입니다. 해당 기기를 점검하세요."),
    ("ET EXPLOIT", "취약점 공격 시도 패턴입니다."),
    ("ET SCAN", "포트·서비스 스캔 패턴입니다."),
    ("ET WEB_CLIENT", "받아온 웹페이지 안에 수상한 모양의 스크립트가 있습니다. 쇼핑몰·광고 페이지에서 오탐이 잦고, 아는 사이트면 대개 정상입니다."),
    ("ET PHISHING", "피싱 사이트로 알려진 곳과의 통신입니다."),
    ("ET USER_AGENTS", "흔하지 않은 프로그램 이름(User-Agent)으로 접속했습니다. 앱·스크립트가 낸 요청이면 대개 정상입니다."),
    ("ET POLICY", "회사 보안 정책에서 흔히 막는 종류의 통신입니다. 직접 쓰는 서비스면 대개 정상입니다."),
    ("ET INFO", "정보성 알림입니다. 어떤 서비스를 썼다는 흔적이며 대개 정상입니다."),
]
KIND_EXPLAIN = {"dns-dga": "무작위처럼 보이는 도메인을 연달아 조회했습니다 (악성코드가 쓰는 방식과 비슷).",
                "bandwidth": "한 시간 사용량이 기준을 넘었습니다.",
                "port-scan": "짧은 시간에 여러 포트로 접속했습니다.",
                "host-scan": "짧은 시간에 여러 주소로 접속했습니다.",
                "dns-blocklist": "차단 목록에 있는 도메인을 조회했습니다."}
DETAIL_KEYS = ("category", "severity", "sid", "proto", "port", "sni", "http", "dns", "domain", "matched", "zone",
               "sample", "hour", "threshold_gb", "distinct_ports", "distinct_hosts")


def explain(kind, title):
    t = title or ""
    for prefix, text in EXPLAIN:
        if t.startswith(prefix):
            return text
    return KIND_EXPLAIN.get(kind)


def alert_detail(a):
    """details 중 화면에 보일 값만, 문자열은 제어문자 제거·길이 제한."""
    d = a.get("details")
    if not isinstance(d, dict):
        return {}
    out = {}
    for k in DETAIL_KEYS:
        v = d.get(k)
        if v in (None, "", [], {}):
            continue
        out[k] = v if isinstance(v, (int, float)) and not isinstance(v, bool) else printable(v)[:160]
    return out


def clean_action(a):
    """watch.py 가 조치 없음을 문자열 "None" 으로 적은 기록도 있다 → None."""
    v = a.get("action")
    return None if v in (None, "", "None") else printable(v)[:160]


def alert_groups(m, since, n=20, per=8):
    """같은 (등급, 제목) 알림을 한 줄로 접는다: 횟수·최근 시각·관련 기기. 등급 높은 것, 최근 것 순.
    클릭해서 펼칠 때 쓰는 값: 쉬운 설명, 목적지별 횟수, 최근 per 건의 기록."""
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
                                                    "count": 0, "first": a["ts"], "last": "", "clients": [],
                                                    "action": None, "_dests": collections.Counter(), "_events": []})
        g["count"] += 1
        g["first"] = min(g["first"], a["ts"])
        if a["ts"] >= g["last"]:
            g["last"] = a["ts"]; g["action"] = clean_action(a) or g["action"]
        name = m.name(a.get("client") or "-")
        if name not in g["clients"]:
            g["clients"].append(name)
        if a.get("dest"):
            g["_dests"][a["dest"]] += 1
        g["_events"].append(a)
    out = sorted(groups.values(), key=lambda g: g["last"], reverse=True)
    out.sort(key=lambda g: LEVEL_RANK.get(g["level"], 9))
    out = out[:n]
    for g in out:
        g["explain"] = explain(g["kind"], g["title"])
        g["dests"] = [{"ip": ip, "count": c, "country": m.country_of(ip), "host": m.hosts.get(ip) or None,
                       "purpose": purpose.purpose(m.hosts.get(ip))}
                      for ip, c in g.pop("_dests").most_common(5)]
        ev = sorted(g.pop("_events"), key=lambda a: a["ts"], reverse=True)[:per]
        g["events"] = [{"ts": a["ts"], "client_name": m.name(a.get("client") or "-"), "dest": a.get("dest"),
                        "country": m.country_of(a.get("dest")),
                        "action": clean_action(a),
                        "detail": alert_detail(a)} for a in ev]
    return out


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


QUIET_SIG_S = 12 * 3600   # 이 시간 넘게 시그니처 탐지가 없으면 "탐지 중단 가능성" 경고


def detection_health(m, now):
    """탐지가 실제로 돌고 있는지. 알림 0건이 '안전'인지 '탐지 불가'인지 구분하려는 지표.
    state: ok / warn(오래 조용함·정보 없음) / bad(규칙 적재 이상·HOME_NET 이 tailnet 아님)."""
    last = None
    for a in m.alerts:
        if a.get("kind") == "ids-alert":
            try:
                last = max(last or 0, datetime.fromisoformat(a["ts"]).timestamp())
            except (KeyError, ValueError, TypeError):
                pass
    engines = ((m.stats.get("detect") or {}).get("engines") or [{}])
    eng = engines[0] if isinstance(engines[0], dict) else {}
    loaded, failed = eng.get("rules_loaded"), eng.get("rules_failed")
    home = None if DEMO else ids_health.yaml_home_net()
    home_ok = None if home is None else ids_health.TAILNET in home
    if home_ok is False or (loaded is not None and (loaded < ids_health.MIN_RULES or failed)):
        state = "bad"
    elif last is None or now - last > QUIET_SIG_S or loaded is None:
        state = "warn"
    else:
        state = "ok"
    return {"state": state, "last_signature": datetime.fromtimestamp(last).isoformat(timespec="seconds") if last else None,
            "age_s": int(now - last) if last else None, "rules_loaded": loaded, "rules_failed": failed,
            "last_reload": eng.get("last_reload"), "home_net_ok": home_ok}


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
    geo = {"home": geo.get("home"), "points": [dict(p) for p in geo.get("points", [])], "source": geo.get("source")}
    seen = {}                                   # 목적지 → (마지막 흐름 시각, 기기). 지구본 툴팁의 "최근 접속 기기"
    for ts, c, ext, port, proto, b, app in m.flows:
        if ts >= seen.get(ext, (0, None))[0]:
            seen[ext] = (ts, c)
    for p in geo["points"]:
        alert = latest.get(p["ip"], (None, None))[1]
        p["last_alert"] = ({k: alert.get(k) for k in ("ts", "level", "title")} if alert else None)
        ts, c = seen.get(p["ip"], (None, None))
        if c is None and alert and alert.get("client"):       # 흐름 기록이 없으면(차단된 곳 등) 마지막 알림의 기기
            ts, c = latest[p["ip"]][0], alert["client"]
        p["purpose"] = purpose.purpose(p.get("host"))
        p["last_client"] = ({"name": m.name(c), "ts": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
                             "ago": ago(ts)} if c else None)
    return {
        "generated": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
        "demo": DEMO,
        "slack": slack_status(),
        # 서버에서 slack-connect 가 대기 중일 때만 승인 주소 (웹 버튼용, 5분 뒤 만료)
        "slack_connect": None if DEMO else slack_connect.read_pending(),
        "host": m.ts_self.get("HostName") or os.uname().nodename,
        "exit_node_approved": bool(m.ts_self.get("ExitNodeOption")),
        "services": dict(m.services),
        "capture": {"packets": pk, "drops": dr, "drop_pct": round(dr / pk * 100, 2) if pk else 0,
                    "uptime_s": m.stats.get("uptime", 0)},
        "alerts_24h": {lv: cnt[lv] for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "nft_visible": IS_ROOT or DEMO,
        "detection": detection_health(m, now),
        "blocked": len(m.nft["blocked"]), "quarantined": len(m.nft["quar"]),
        "destination_count": len({ext for ts, c, ext, port, proto, b, app in m.flows if now - ts <= 120}),
        "attention_dests": [
            {"ip": ip, "blocked": ip in m.nft["blocked"],
             "city": next((p.get("city") for p in geo["points"] if p["ip"] == ip), None) or m.country_of(ip),
             "host": next((p.get("host") for p in geo["points"] if p["ip"] == ip), None),
             "last_alert": ({k: latest[ip][1].get(k) for k in ("ts", "level", "title")} if ip in latest else None)}
            for ip in sorted(set(m.nft["blocked"]) | {ip for ip, (ts, a) in latest.items() if ts > day},
                             key=lambda ip: (ip not in m.nft["blocked"],
                                             LEVEL_RANK.get(latest.get(ip, (None, {}))[1].get("level"), 9)))],
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
                    "client_name": m.name(c), "label": label, "purpose": purpose.purpose(label)}
                   for ts, c, label in m.recent_dests(30)],
    }
