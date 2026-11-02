#!/usr/bin/env python3
"""ExitGuard 일일/온디맨드 리포트: 집계 state + alerts.jsonl 로 요약 생성."""
import collections, glob, json, os, subprocess, sys, time
from datetime import datetime, timedelta
from common import load_config, Notifier, nft_list_set, LEVELS


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def ts_names():
    """tailscale IP -> hostname 매핑."""
    m = {}
    try:
        out = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10).stdout
        st = json.loads(out)
        for p in list(st.get("Peer", {}).values()) + [st.get("Self", {})]:
            for ip in p.get("TailscaleIPs", []) or []:
                m[ip] = p.get("HostName", "")
    except Exception:
        pass
    return m


def main():
    cfg = load_config()
    state = cfg.get("state_dir", "/var/lib/exitguard")
    logd = cfg.get("log_dir", "/var/log/exitguard")
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    since = datetime.now() - timedelta(days=days)
    names = ts_names()

    def nm(ip):
        return f"{ip} ({names[ip]})" if ip in names else ip

    # 집계 파일 합산
    agg = {}
    for d in range(days + 1):
        day = (datetime.now() - timedelta(days=d)).strftime("%Y%m%d")
        p = os.path.join(state, f"agg-{day}.json")
        if not os.path.exists(p):
            continue
        with open(p) as f:
            for c, g in json.load(f).items():
                a = agg.setdefault(c, {"bytes_out": 0, "bytes_in": 0, "flows": 0,
                                       "dests": collections.Counter(), "dns": collections.Counter(),
                                       "alerts": collections.Counter()})
                a["bytes_out"] += g["bytes_out"]; a["bytes_in"] += g["bytes_in"]; a["flows"] += g["flows"]
                for k in ("dests", "dns", "alerts"):
                    a[k].update(dict(g[k]))

    # 알림
    alerts = []
    ap = os.path.join(logd, "alerts.jsonl")
    if os.path.exists(ap):
        with open(ap) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if datetime.fromisoformat(r["ts"]).replace(tzinfo=None) >= since:
                        alerts.append(r)
                except Exception:
                    pass

    L = []
    L.append(f"# ExitGuard 리포트 ({since:%Y-%m-%d %H:%M} ~ {datetime.now():%Y-%m-%d %H:%M})")
    L.append("")
    by_level = collections.Counter(a["level"] for a in alerts)
    L.append("## 요약")
    L.append(f"- 활성 클라이언트: {len(agg)}")
    L.append(f"- 총 전송량: ↑{human(sum(a['bytes_out'] for a in agg.values()))} ↓{human(sum(a['bytes_in'] for a in agg.values()))}")
    L.append("- 알림: " + ", ".join(f"{k} {by_level[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if by_level[k]) or "- 알림: 없음")
    actions = [a for a in alerts if a.get("action") and "실패" not in a["action"]]
    L.append(f"- 자동 조치(차단/격리): {len(actions)}건")
    L.append("")

    blocked = nft_list_set("blocked")
    quar = nft_list_set("quarantine")
    L.append("## 현재 차단 상태")
    L.append(f"- 차단된 목적지: {len(blocked)}개" + (": " + ", ".join(list(blocked)[:20]) if blocked else ""))
    L.append(f"- 격리된 클라이언트: {len(quar)}개" + (": " + ", ".join(nm(x) for x in quar) if quar else ""))
    L.append("")

    L.append("## 클라이언트별 사용량")
    L.append("| 클라이언트 | 업로드 | 다운로드 | 플로우 | 알림 |")
    L.append("|---|---|---|---|---|")
    for c, a in sorted(agg.items(), key=lambda x: -(x[1]["bytes_out"] + x[1]["bytes_in"])):
        L.append(f"| {nm(c)} | {human(a['bytes_out'])} | {human(a['bytes_in'])} | {a['flows']} | {sum(a['alerts'].values())} |")
    L.append("")

    hi = [a for a in alerts if LEVELS.get(a["level"], 0) >= 2]
    L.append(f"## 주요 알림 (MEDIUM 이상, {len(hi)}건)")
    grouped = collections.Counter((a["level"], a["kind"], a["title"], a.get("client")) for a in hi)
    for (lv, kind, title, client), n in grouped.most_common(40):
        L.append(f"- [{lv}] {kind}: {title} — 클라이언트 {nm(client) if client else '-'} ×{n}")
    L.append("")

    if actions:
        L.append("## 자동 조치 내역")
        for a in actions[-30:]:
            L.append(f"- {a['ts']} {nm(a.get('client') or '-')} → {a.get('dest') or '-'}: {a['action']} ({a['title']})")
        L.append("")

    L.append("## 클라이언트별 상위 목적지 / 도메인")
    for c, a in agg.items():
        L.append(f"### {nm(c)}")
        if a["dests"]:
            L.append("- 목적지: " + ", ".join(f"{d}×{n}" for d, n in a["dests"].most_common(10)))
        if a["dns"]:
            L.append("- DNS: " + ", ".join(f"{d}×{n}" for d, n in a["dns"].most_common(10)))
        if a["alerts"]:
            L.append("- IDS: " + ", ".join(f"{d}×{n}" for d, n in a["alerts"].most_common(5)))
        L.append("")

    text = "\n".join(L)
    os.makedirs(os.path.join(logd, "reports"), exist_ok=True)
    out = os.path.join(logd, "reports", f"report-{datetime.now():%Y%m%d-%H%M}.md")
    with open(out, "w") as f:
        f.write(text)
    print(text)
    if "--notify" in sys.argv:
        n = Notifier(cfg)
        summary = "\n".join(L[:12])
        n._webhook(summary); n._telegram(summary)
        n._desktop("INFO", "일일 리포트", summary)
    return out


if __name__ == "__main__":
    main()
