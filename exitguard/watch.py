#!/usr/bin/env python3
"""ExitGuard watcher: Suricata eve.json 을 실시간으로 읽어
의심 정황을 탐지·보고하고 nftables 로 차단/격리한다."""
import collections, json, math, os, signal, sys, time
from common import (load_config, nets, ip_in, nft_add, Notifier, now_iso)


class Window:
    """슬라이딩 윈도우 카운터 (key -> deque of (ts, value))."""
    def __init__(self, sec):
        self.sec = sec
        self.d = collections.defaultdict(collections.deque)

    def add(self, key, value, ts=None):
        ts = ts or time.time()
        q = self.d[key]
        q.append((ts, value))
        cutoff = ts - self.sec
        while q and q[0][0] < cutoff:
            q.popleft()
        return q

    def distinct(self, key):
        return len({v for _, v in self.d.get(key, ())})

    def count(self, key):
        return len(self.d.get(key, ()))


def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


class Watcher:
    def __init__(self, cfg):
        self.cfg = cfg
        self.home = nets(cfg["home_nets"])
        self.never_block = nets(cfg["never_block"])
        self.nf = Notifier(cfg)
        self.state_dir = cfg.get("state_dir", "/var/lib/exitguard")
        os.makedirs(self.state_dir, exist_ok=True)

        b = cfg["block"]
        self.block_enabled = b.get("enabled", True)
        self.block_sev = set(b.get("block_on_severity", [1]))
        self.block_cats = set(b.get("block_categories", []))
        self.ignore_cats = set(b.get("ignore_categories", []))
        self.block_hours = b.get("dest_block_hours", 24)
        self.cat_levels = b.get("category_levels", {})
        self.sig_levels = sorted(b.get("signature_levels", {}).items(), key=lambda kv: -len(kv[0]))

        q = cfg["quarantine"]
        self.q_enabled = q.get("enabled", True)
        self.q_thresh = q.get("high_alerts", 5)
        self.q_hours = q.get("hours", 1)
        self.high_win = Window(q.get("window_sec", 600))
        self.quarantined = {}

        s = cfg["scan"]
        self.scan_cfg = s
        self.hscan_exclude = set(s.get("horizontal_exclude_ports", []))
        self.vscan = Window(s.get("window_sec", 60))   # (client,dst) -> ports
        self.hscan = Window(s.get("window_sec", 60))   # (client,port) -> hosts
        self.scan_flagged = {}

        d = cfg["dns"]
        self.dns_cfg = d
        self.nx_win = Window(300)
        self.tunnel_win = Window(300)
        self.sus_tlds = tuple(d.get("suspicious_tlds", []))
        self.blocklist_domains = [x.lower().lstrip(".") for x in d.get("blocklist_domains", [])]

        self.bw_warn = cfg["bandwidth"].get("gb_per_hour_warn", 5) * (1024 ** 3)
        self.bw_hour = {}     # client -> (hour_key, bytes)
        self.bw_flagged = set()

        self.sus_ports = {"tcp": set(cfg["suspicious_ports"].get("tcp", [])),
                          "udp": set(cfg["suspicious_ports"].get("udp", []))}

        # 일일 리포트용 집계 (hour 단위로 state 파일에 flush)
        self.agg = collections.defaultdict(lambda: {"bytes_out": 0, "bytes_in": 0, "flows": 0,
                                                     "dests": collections.Counter(),
                                                     "dns": collections.Counter(),
                                                     "alerts": collections.Counter()})
        self.last_flush = time.time()

    # ------------------------------------------------------------ helpers
    def is_home(self, ip):
        return ip_in(ip, self.home)

    def sides(self, ev):
        """(client_ip, external_ip, dest_port) 반환. 둘 다 home 이면 external=None."""
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        if self.is_home(src) and not self.is_home(dst):
            return src, dst, ev.get("dest_port")
        if self.is_home(dst) and not self.is_home(src):
            return dst, src, ev.get("src_port")
        if self.is_home(src):
            return src, None, ev.get("dest_port")
        return None, dst, ev.get("dest_port")

    def block_dest(self, ip, reason):
        if not self.block_enabled or not ip or ip_in(ip, self.never_block):
            return None
        ok, err = nft_add("blocked", ip, self.block_hours)
        if ok:
            self._append_state("blocks.jsonl", {"ts": now_iso(), "ip": ip, "hours": self.block_hours, "reason": reason})
            return f"목적지 {ip} 를 {self.block_hours}시간 차단"
        print(f"nft block failed for {ip}: {err}", file=sys.stderr, flush=True)
        return f"차단 실패({err})"

    def quarantine(self, client, reason):
        if not self.q_enabled or not client:
            return None
        if self.quarantined.get(client, 0) > time.time():
            return "이미 격리됨"
        ok, err = nft_add("quarantine", client, self.q_hours)
        if ok:
            self.quarantined[client] = time.time() + self.q_hours * 3600
            self._append_state("quarantines.jsonl", {"ts": now_iso(), "client": client, "hours": self.q_hours, "reason": reason})
            return f"클라이언트 {client} 를 {self.q_hours}시간 격리(전체 포워딩 차단)"
        return f"격리 실패({err})"

    def _append_state(self, name, rec):
        with open(os.path.join(self.state_dir, name), "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def note_high(self, client, title):
        """HIGH 알림 누적 → 임계치 초과 시 격리."""
        if not client:
            return None
        q = self.high_win.add(client, title)
        if len(q) >= self.q_thresh:
            act = self.quarantine(client, f"{len(q)} high alerts in window")
            if act and not act.startswith("이미"):
                self.nf.emit("CRITICAL", "quarantine",
                             f"클라이언트 자동 격리: {self.q_thresh}회 이상 고위험 알림",
                             client=client, action=act,
                             details={"recent": list({v for _, v in q})[:5]})
            return act
        return None

    # ------------------------------------------------------------ handlers
    def on_alert(self, ev):
        a = ev.get("alert", {})
        sev = a.get("severity", 3)
        cat = a.get("category", "")
        sig = a.get("signature", "")
        if cat in self.ignore_cats:
            return
        client, ext, port = self.sides(ev)
        if client:
            self.agg[client]["alerts"][f"[{sev}] {sig}"] += 1

        level = next((lv for pre, lv in self.sig_levels if sig.startswith(pre)), None) \
            or self.cat_levels.get(cat) or {1: "HIGH", 2: "MEDIUM"}.get(sev, "LOW")
        malicious = sev in self.block_sev and (not self.block_cats or cat in self.block_cats)
        action = None
        if malicious:
            action = self.block_dest(ext, f"{sig}")
        if level == "HIGH" and malicious:
            qa = self.note_high(client, sig)
            if qa:
                action = f"{action or ''}; {qa}".strip("; ")

        details = {"signature": sig, "category": cat, "severity": sev,
                   "proto": ev.get("proto"), "port": port, "sid": a.get("signature_id")}
        for k in ("http", "tls", "dns"):
            if k in ev:
                v = ev[k]
                if k == "http":
                    details["http"] = f"{v.get('http_method', '')} {v.get('hostname', '')}{v.get('url', '')}"
                elif k == "tls":
                    details["sni"] = v.get("sni")
                elif k == "dns":
                    details["dns"] = v.get("rrname") or (v.get("queries") or [{}])[0].get("rrname")
        self.nf.emit(level, "ids-alert", sig, client=client, dest=ext, action=action, details=details,
                     dedupe_key=f"alert|{a.get('signature_id')}|{client}|{ext}")

    def on_flow(self, ev):
        fl = ev.get("flow", {})
        client, ext, port = self.sides(ev)
        if not client:
            return
        proto = (ev.get("proto") or "").lower()
        up, down = fl.get("bytes_toserver", 0), fl.get("bytes_toclient", 0)
        if ev.get("dest_ip") == client:  # 방향 뒤집힘
            up, down = down, up
        g = self.agg[client]
        g["bytes_out"] += up
        g["bytes_in"] += down
        g["flows"] += 1
        if ext:
            g["dests"][f"{ext}:{port}/{proto}"] += 1

        # Suricata 재시작 시 한꺼번에 쏟아지는 플로우(reason=shutdown)는 통계에만 반영하고 휴리스틱은 건너뜀
        if fl.get("reason") == "shutdown":
            return

        # 대역폭
        hour = time.strftime("%Y%m%d%H")
        hk, hb = self.bw_hour.get(client, (hour, 0))
        if hk != hour:
            hb = 0
            self.bw_flagged.discard(client)
        hb += up + down
        self.bw_hour[client] = (hour, hb)
        if hb > self.bw_warn and client not in self.bw_flagged:
            self.bw_flagged.add(client)
            self.nf.emit("LOW", "bandwidth", f"시간당 전송량 {hb / 1024**3:.1f} GB 초과", client=client,
                         details={"hour": hour, "threshold_gb": self.cfg["bandwidth"]["gb_per_hour_warn"]})

        if not ext or proto not in ("tcp", "udp"):
            return

        # 의심 포트 (룰 없는 UDP 등 보강)
        if port in self.sus_ports.get(proto, ()):
            self.nf.emit("LOW", "sus-port", f"의심 포트 {port}/{proto} 접속", client=client, dest=ext,
                         details={"state": fl.get("state"), "bytes": up + down})

        # 포트스캔 (수직: 한 호스트 다수 포트 / 수평: 한 포트 다수 호스트)
        s = self.scan_cfg
        ts = time.time()
        self.vscan.add((client, ext), port, ts)
        vp = self.vscan.distinct((client, ext))
        hh = 0
        if port not in self.hscan_exclude:
            self.hscan.add((client, port), ext, ts)
            hh = self.hscan.distinct((client, port))
        if vp >= s["vertical_ports"] and self.scan_flagged.get(("v", client, ext), 0) < ts - 600:
            self.scan_flagged[("v", client, ext)] = ts
            act = self.block_dest(ext, "port scan target") if s.get("block_scanned_dest") else None
            self.nf.emit("MEDIUM", "portscan", f"포트 스캔 의심: {ext} 에 {vp}개 포트", client=client, dest=ext,
                         action=act, details={"distinct_ports": vp, "window_sec": s["window_sec"]})
        if hh >= s["horizontal_hosts"] and self.scan_flagged.get(("h", client, port), 0) < ts - 600:
            self.scan_flagged[("h", client, port)] = ts
            self.nf.emit("MEDIUM", "hostsweep", f"호스트 스윕 의심: 포트 {port}/{proto} 로 {hh}개 호스트",
                         client=client, details={"distinct_hosts": hh, "window_sec": s["window_sec"]})

    def on_dns(self, ev):
        d = ev.get("dns", {})
        client, ext, _ = self.sides(ev)
        if not client:
            return
        # v2 / v3 포맷 모두 처리
        names, rcode = [], d.get("rcode")
        if d.get("rrname"):
            names.append(d["rrname"])
        for q in d.get("queries") or []:
            if q.get("rrname"):
                names.append(q["rrname"])
        typ = d.get("type")
        for name in names:
            name_l = name.lower().rstrip(".")
            if typ in ("query", "request"):
                self.agg[client]["dns"][name_l] += 1
                # 블랙리스트 도메인
                for bad in self.blocklist_domains:
                    if name_l == bad or name_l.endswith("." + bad):
                        self.nf.emit("HIGH", "dns-blocklist", f"차단 목록 도메인 질의: {name_l}", client=client,
                                     details={"domain": name_l, "matched": bad})
                        self.note_high(client, f"dns-blocklist {bad}")
                # 의심 TLD
                if name_l.endswith(self.sus_tlds):
                    self.nf.emit("LOW", "dns-tld", f"의심 TLD 질의: {name_l}", client=client,
                                 dedupe_key=f"tld|{client}|{name_l}")
                # 터널링: 긴 라벨 + 고엔트로피, 같은 zone 반복
                labels = name_l.split(".")
                zone = ".".join(labels[-2:])
                sub = ".".join(labels[:-2])
                if len(sub) >= self.dns_cfg["long_label_len"] and entropy(sub) > 3.5:
                    q = self.tunnel_win.add((client, zone), name_l)
                    if len(q) >= self.dns_cfg["tunnel_queries_per_5min"]:
                        self.tunnel_win.d.pop((client, zone), None)
                        self.nf.emit("MEDIUM", "dns-tunnel", f"DNS 터널링 의심: {zone}", client=client,
                                     details={"zone": zone, "sample": name_l[:80], "queries_5min": len(q)})
            # NXDOMAIN 폭주 (DGA)
            if rcode == "NXDOMAIN":
                q = self.nx_win.add(client, name_l)
                if len(q) >= self.dns_cfg["nxdomain_per_5min"]:
                    self.nx_win.d.pop(client, None)
                    self.nf.emit("MEDIUM", "dns-dga", f"NXDOMAIN 폭주 {len(q)}회/5분 (DGA 멀웨어 의심)", client=client,
                                 details={"samples": [v for _, v in list(q)[-5:]]})

    def on_anomaly(self, ev):
        client, ext, _ = self.sides(ev)
        an = ev.get("anomaly", {})
        if client:
            self.agg[client]["alerts"][f"[anomaly] {an.get('event')}"] += 1

    # ------------------------------------------------------------ main loop
    def flush_agg(self, force=False):
        if not force and time.time() - self.last_flush < 300:
            return
        self.last_flush = time.time()
        out = {}
        for c, g in self.agg.items():
            out[c] = {"bytes_out": g["bytes_out"], "bytes_in": g["bytes_in"], "flows": g["flows"],
                      "dests": g["dests"].most_common(50), "dns": g["dns"].most_common(50),
                      "alerts": g["alerts"].most_common(50)}
        path = os.path.join(self.state_dir, f"agg-{time.strftime('%Y%m%d')}.json")
        # 하루 단위로 누적 저장: 기존 파일과 합산
        if os.path.exists(path):
            try:
                with open(path) as f:
                    old = json.load(f)
            except Exception:
                old = {}
        else:
            old = {}
        for c, g in out.items():
            o = old.setdefault(c, {"bytes_out": 0, "bytes_in": 0, "flows": 0, "dests": [], "dns": [], "alerts": []})
            o["bytes_out"] += g["bytes_out"]; o["bytes_in"] += g["bytes_in"]; o["flows"] += g["flows"]
            for key in ("dests", "dns", "alerts"):
                cnt = collections.Counter(dict(o[key]))
                cnt.update(dict(g[key]))
                o[key] = cnt.most_common(50)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(old, f, ensure_ascii=False)
        os.replace(tmp, path)
        self.agg.clear()

    def handle(self, ev):
        t = ev.get("event_type")
        if t == "alert":
            self.on_alert(ev)
        elif t == "flow":
            self.on_flow(ev)
        elif t == "dns":
            self.on_dns(ev)
        elif t == "anomaly":
            self.on_anomaly(ev)

    def tail(self, path):
        """로그 로테이션(inode 변경/truncate)을 처리하는 tail -F."""
        print(f"ExitGuard watcher started, tailing {path}", flush=True)
        f = None
        inode = None
        while True:
            try:
                if f is None:
                    while not os.path.exists(path):
                        time.sleep(2)
                    f = open(path, "rb")   # 바이너리: 부분 줄을 만나면 tell/seek 로 되돌릴 수 있게
                    st = os.fstat(f.fileno())
                    inode = st.st_ino
                    f.seek(0, os.SEEK_END)  # 시작 시 기존 로그는 건너뜀
                pos = f.tell()
                line = f.readline()
                if line.endswith(b"\n"):
                    try:
                        self.handle(json.loads(line))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                    except Exception as e:
                        print(f"handler error: {e}", file=sys.stderr, flush=True)
                    continue
                if line:                    # Suricata 가 쓰는 중인 부분 줄: 되돌려 두고 다음 턴에 다시 읽음
                    f.seek(pos)
                # EOF: 로테이션 확인
                self.flush_agg()
                try:
                    st = os.stat(path)
                    if st.st_ino != inode or st.st_size < f.tell():
                        f.close(); f = None
                        continue
                except FileNotFoundError:
                    f.close(); f = None
                    continue
                time.sleep(0.5)
            except KeyboardInterrupt:
                break
        self.flush_agg(force=True)


if __name__ == "__main__":
    cfg = load_config()
    w = Watcher(cfg)

    def _term(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)
    try:
        w.tail(cfg.get("eve_log", "/var/log/suricata/eve.json"))
    finally:
        w.flush_agg(force=True)
