import json, collections, ipaddress, statistics, subprocess, sys
from datetime import datetime
EVE="/var/log/suricata/eve.json"
HOME=[ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48")]
"""ExitGuard 심층 분석: eve.json 전체를 기기별로 훑어 특이사항 후보를 출력. 사용: exitguardctl analyze [호스트명...]"""
NAMES={}
try:
    _st=json.loads(subprocess.run(["tailscale","status","--json"],capture_output=True,text=True,timeout=10).stdout)
    for _p in list(_st.get("Peer",{}).values()):
        for _ip in _p.get("TailscaleIPs") or []: NAMES[_ip]=_p.get("HostName","?")
except Exception: pass
_want=[a.lower() for a in sys.argv[1:]]
if _want: NAMES={ip:n for ip,n in NAMES.items() if n.lower() in _want}
def home(ip):
    try: a=ipaddress.ip_address(ip)
    except: return False
    return any(a in n for n in HOME)
def norm(ip):
    try: return ipaddress.ip_address(ip).compressed
    except: return ip
D=collections.defaultdict(lambda: dict(flows=[],tls=[],quic=[],dns=[],http=[],alerts=[],anom=[],files=[],inbound=[]))
for line in open(EVE, errors="replace"):
    try: ev=json.loads(line)
    except: continue
    t=ev.get("event_type")
    if t=="stats": continue
    src,dst=norm(ev.get("src_ip","")),norm(ev.get("dest_ip",""))
    if home(src) and not home(dst): c,ext,port,outb=src,dst,ev.get("dest_port"),True
    elif home(dst) and not home(src): c,ext,port,outb=dst,src,ev.get("src_port"),False
    else: continue
    name=NAMES.get(c); 
    if not name: continue
    ts=ev["timestamp"]
    d=D[name]
    if t=="flow":
        fl=ev["flow"]
        if not outb and fl.get("state")=="new" and fl.get("pkts_toclient",0)==0: d["inbound"].append((ts,ext,ev.get("dest_port"),ev.get("proto")))
        up,down=(fl.get("bytes_toserver",0),fl.get("bytes_toclient",0)) if outb else (fl.get("bytes_toclient",0),fl.get("bytes_toserver",0))
        d["flows"].append(dict(ts=ts,ext=ext,port=port,proto=(ev.get("proto") or "").lower(),app=ev.get("app_proto") or "-",up=up,down=down,age=fl.get("age",0),state=fl.get("state"),reason=fl.get("reason"),start=fl.get("start"),pk=fl.get("pkts_toserver",0)+fl.get("pkts_toclient",0)))
    elif t in("tls","quic"):
        x=ev.get(t,{}); d[t].append(dict(ts=ts,ext=ext,port=port,sni=x.get("sni"),ver=x.get("version"),ja4=x.get("ja4"),issuer=x.get("issuerdn"),subject=x.get("subject"),notafter=x.get("notafter")))
    elif t=="dns": d["dns"].append((ts,ext,ev["dns"]))
    elif t=="http":
        h=ev["http"]; d["http"].append(dict(ts=ts,ext=ext,host=h.get("hostname"),url=(h.get("url") or "")[:80],ua=h.get("http_user_agent"),method=h.get("http_method"),status=h.get("status"),ct=h.get("http_content_type")))
    elif t=="alert": a=ev["alert"]; d["alerts"].append((a.get("severity"),a.get("signature"),ext))
    elif t=="anomaly": d["anom"].append((ev["anomaly"].get("event"),ev.get("app_proto"),ext))
    elif t=="fileinfo": f=ev["fileinfo"]; d["files"].append((ext,f.get("filename"),f.get("magic"),f.get("size"),(ev.get("http") or {}).get("hostname")))

def hb(n):
    for u in "B KB MB GB".split():
        if n<1024: return f"{n:.1f}{u}"
        n/=1024
    return f"{n:.1f}TB"
rdns_cache={}
def rdns(ip):
    if ip in rdns_cache: return rdns_cache[ip]
    try: r=subprocess.run(["dig","+short","+time=1","+tries=1","-x",ip],capture_output=True,text=True,timeout=3).stdout.strip().split("\n")[0].rstrip(".")
    except: r=""
    rdns_cache[ip]=r or "-"; return rdns_cache[ip]

for name in sorted(D, key=lambda n: -len(D[n]["flows"])):
    d=D[name]; fl=[f for f in d["flows"] if f["reason"]!="shutdown"]; allf=d["flows"]
    print("="*100); print(f"### {name}")
    if allf:
        tss=sorted(f["ts"] for f in allf); print(f"기간: {tss[0][11:19]} ~ {tss[-1][11:19]}  플로우 {len(allf)}개 (재시작 플러시 {len(allf)-len(fl)}개 포함)")
    print(f"전송량(전체): ↑{hb(sum(f['up'] for f in allf))} ↓{hb(sum(f['down'] for f in allf))}")
    # SNI map ip->names
    sni_of=collections.defaultdict(set)
    for x in d["tls"]+d["quic"]:
        if x["sni"]: sni_of[x["ext"]].add(x["sni"])
    print("\n[목적지 TOP 12 by bytes]")
    agg=collections.defaultdict(lambda:[0,0,0])
    for f in allf: a=agg[(f["ext"],f["port"],f["proto"])]; a[0]+=f["up"]; a[1]+=f["down"]; a[2]+=1
    for (ip,port,proto),(up,down,n) in sorted(agg.items(),key=lambda kv:-(kv[1][0]+kv[1][1]))[:12]:
        label=",".join(sorted(sni_of.get(ip,[]))[:2]) or rdns(ip)
        print(f"  {ip:<16} {str(port)+'/'+proto:<10} ↑{hb(up):>8} ↓{hb(down):>8} x{n:<4} {label}")
    print(f"\n[포트/프로토콜 분포]  고유 목적지 IP: {len({f['ext'] for f in allf})}")
    pc=collections.Counter(f"{f['port']}/{f['proto']}" for f in fl); print("  "+", ".join(f"{k}:{v}" for k,v in pc.most_common(10)))
    ac=collections.Counter(f["app"] for f in fl); print("  app: "+", ".join(f"{k}:{v}" for k,v in ac.most_common(10)))
    odd=[f for f in fl if f["port"] not in (80,443,853,53,123) and f["proto"] in("tcp","udp")]
    if odd:
        oc=collections.Counter((f["ext"],f["port"],f["proto"],f["app"]) for f in odd)
        print("  비표준 포트 접속:"); 
        for (ip,port,proto,app),n in oc.most_common(12): print(f"    {ip:<16} {port}/{proto} app={app} x{n} {','.join(sorted(sni_of.get(ip,[]))[:1]) or rdns(ip)}")
    # failed / no-reply flows
    nr=[f for f in fl if f["down"]==0 and f["proto"] in ("tcp","udp")]
    print(f"\n[응답 없는 아웃바운드 플로우] {len(nr)}개 / {len(fl)}")
    nc=collections.Counter((f["ext"],f["port"],f["proto"]) for f in nr)
    for (ip,port,proto),n in nc.most_common(6): print(f"    {ip:<16} {port}/{proto} x{n} {','.join(sorted(sni_of.get(ip,[]))[:1]) or rdns(ip)}")
    # inbound unsolicited
    print(f"[외부→기기 미요청 유입] {len(d['inbound'])}개", d["inbound"][:3])
    # TLS
    T=d["tls"]; Q=d["quic"]
    print(f"\n[TLS {len(T)} / QUIC {len(Q)}]")
    vc=collections.Counter(x["ver"] for x in T); print("  TLS 버전: "+", ".join(f"{k}:{v}" for k,v in vc.most_common()))
    nosni=[x for x in T+Q if not x["sni"]]
    print(f"  SNI 없는 연결: {len(nosni)}개 -> "+", ".join(f"{ip}({n})" for ip,n in collections.Counter(x['ext'] for x in nosni).most_common(5)))
    rawip=[x for x in T+Q if x["sni"] and x["sni"].replace('.','').isdigit()]
    if rawip: print(f"  SNI 가 IP 인 연결: {len(rawip)}")
    iss=collections.Counter((x["issuer"] or "").split("O=")[-1].split(",")[0] for x in T if x["issuer"]); print("  인증서 발급자 TOP: "+", ".join(f"{k}:{v}" for k,v in iss.most_common(6)))
    selfsigned=[x for x in T if x["issuer"] and x["subject"] and x["issuer"]==x["subject"]]
    if selfsigned: print(f"  자체서명 인증서: {len(selfsigned)} -> "+", ".join({x['sni'] or x['ext'] for x in selfsigned}))
    expired=[x for x in T if x["notafter"] and x["notafter"]<datetime.now().strftime("%Y-%m-%dT%H:%M:%S")]
    if expired: print(f"  만료 인증서: {len(expired)} -> "+", ".join({x['sni'] or x['ext'] for x in expired}))
    doms=collections.Counter()
    for x in T+Q:
        if x["sni"]: 
            p=x["sni"].split("."); doms[".".join(p[-2:]) if not (len(p)>2 and p[-2] in("co","com","or","go","ne") and len(p[-1])==2) else ".".join(p[-3:])]+=1
    print(f"  고유 SNI: {len({x['sni'] for x in T+Q if x['sni']})}  / 도메인(2차) {len(doms)}개 TOP: "+", ".join(f"{k}:{v}" for k,v in doms.most_common(25)))
    ja=collections.Counter(x["ja4"] for x in T if x["ja4"]); print("  JA4 종류 "+str(len(ja))+": "+", ".join(f"{k}:{v}" for k,v in ja.most_common(5)))
    # HTTP plaintext
    H=d["http"]; print(f"\n[평문 HTTP {len(H)}]")
    hc=collections.Counter((h["host"],h["method"]) for h in H)
    for (host,m),n in hc.most_common(8): print(f"    {m} {host} x{n}")
    uas=collections.Counter(h["ua"] for h in H if h["ua"]); 
    if uas: print("  UA: "+" | ".join(f"{(k or '')[:60]}:{v}" for k,v in uas.most_common(4)))
    if d["files"]: print("  파일 전송: "+"; ".join(f"{h or ip}:{fn} [{(mg or '')[:25]}] {sz}B" for ip,fn,mg,sz,h in d["files"][:6]))
    # DNS
    print(f"\n[DNS {len(d['dns'])}]")
    qn=collections.Counter(); rc=collections.Counter()
    for ts,ext,x in d["dns"]:
        for q in (x.get("queries") or [{"rrname":x.get("rrname")}]): 
            if q.get("rrname"): qn[q["rrname"]]+=1
        if x.get("rcode"): rc[x["rcode"]]+=1
    print("  서버: "+", ".join(f"{k}:{v}" for k,v in collections.Counter(e for _,e,_ in d["dns"]).most_common(3))+" | rcode: "+", ".join(f"{k}:{v}" for k,v in rc.most_common()))
    print("  질의 TOP: "+", ".join(f"{k}:{v}" for k,v in qn.most_common(10)))
    # alerts, anomalies
    print(f"\n[IDS 알림 {len(d['alerts'])}]")
    for (sev,sig,ext),n in collections.Counter(d["alerts"]).most_common(10): print(f"    sev{sev} x{n} {sig} -> {ext}")
    print(f"[프로토콜 이상 {len(d['anom'])}] "+", ".join(f"{e}/{a}->{ip}" for e,a,ip in d["anom"][:6]))
    # beaconing: same dest, regular intervals
    print("\n[주기성(비코닝) 후보: 같은 목적지로 8회 이상, 간격 표준편차 작음]")
    bydst=collections.defaultdict(list)
    for f in fl:
        if f["start"]: bydst[(f["ext"],f["port"])].append(datetime.fromisoformat(f["start"]).timestamp())
    found=0
    for (ip,port),tl in bydst.items():
        if len(tl)<8: continue
        tl.sort(); gaps=[b-a for a,b in zip(tl,tl[1:]) if b-a>0.5]
        if len(gaps)<6: continue
        m=statistics.mean(gaps); sd=statistics.pstdev(gaps)
        if m>5 and sd/m<0.25:
            found+=1; print(f"    {ip}:{port} n={len(tl)} 평균간격 {m:.0f}s (cv {sd/m:.2f}) {','.join(sorted(sni_of.get(ip,[]))[:1]) or rdns(ip)}")
    if not found: print("    없음")
    # long-lived
    ll=sorted(fl,key=lambda f:-f["age"])[:4]
    print("[장시간 연결 TOP] "+"; ".join(f"{f['ext']}:{f['port']} {f['age']}s {','.join(sorted(sni_of.get(f['ext'],[]))[:1])}" for f in ll))
