"""ExitGuard 텍스트판 화면: curses 대시보드(exitguard-top)와 --text 스냅샷. 데이터는 core 에서 받는다."""
import collections, curses, os, subprocess, time
from datetime import datetime

import core
from core import ago, clip, first_fit, fit, human, printable, run, wcwidth


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
        s = clip(printable(s), max(0, maxw - 1 if y == h - 1 else maxw))   # 글자 수가 아닌 표시 폭 기준 (한글 2칸)
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
        self.put(1, x + len(s) + 2, f"│ 차단 {nb}  격리 {nq}" if core.IS_ROOT else "│ 차단/격리: root 필요", curses.color_pair(1 if nq else 0))
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
        blc = [f"차단 {nb}  격리 {nq}", f"차단{nb} 격리{nq}"] if core.IS_ROOT else ["차단/격리: root 필요", "조치: root", "root"]
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
            foot = " q 종료  +/- 주기  " + ("b 차단  u 해제  Q 격리  R 격리해제  c pcap " if core.IS_ROOT else "(조치하려면 sudo 로 실행) ") + msg
        else:
            if core.IS_ROOT:
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
        rate_hdr = "속도/s " if core.IS_ROOT else "5분량 "
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
            if k in ("q", "Q") and not (k == "Q" and core.IS_ROOT):
                return
            if k == "KEY_RESIZE":
                self.draw()
            elif k == "+":
                self.interval = min(30, self.interval + 1); last = 0
            elif k == "-":
                self.interval = max(1, self.interval - 1); last = 0
            elif k in ("b", "u", "Q", "R", "c") and core.IS_ROOT:
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
