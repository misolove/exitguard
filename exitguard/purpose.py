"""목적지 이름(SNI·DNS·HTTP 호스트) → 짧은 한국어 용도 설명. 사람이 고른 고정 표 (AI·네트워크 조회 없음).

규칙: 호스트가 표의 이름과 같거나 그 하위 도메인이면 맞음. 여러 개가 맞으면 가장 긴(구체적인) 것.
표에 없으면 None (화면은 용도를 생략). 새 서비스는 아래 표에 한 줄 추가.
확인되지 않고 기록으로 짐작만 한 것은 설명을 "추정: " 으로 시작한다 (확인된 설명과 섞이지 않게).
"""

PURPOSE = {
    # 증권·금융
    "tossinvest.com": "토스증권 시세·주문", "toss.im": "토스 앱", "koreainvestment.com": "한국투자증권 시세·주문",
    "miraeasset.com": "미래에셋증권", "kbsec.com": "KB증권", "kbanknow.com": "케이뱅크", "bithumb.com": "빗썸 거래소",
    "krx.co.kr": "한국거래소 시세·공시", "stocknow.ai": "StockNow 주식 정보", "stockplus.com": "증권플러스",
    "alphasquare.co.kr": "알파스퀘어 차트", "tradingview.com": "TradingView 차트", "wowtv.co.kr": "한국경제TV",
    "stripe.com": "Stripe 결제",
    # 포털·메신저·국내 앱
    "naver.com": "네이버", "naver.net": "네이버 콘텐츠", "pstatic.net": "네이버 이미지·파일", "navercorp.com": "네이버 서비스",
    "daum.net": "다음", "kakao.com": "카카오", "kakaocdn.net": "카카오 이미지·파일", "onkakao.net": "카카오톡 서버",
    "band.us": "네이버 밴드", "karrotmarket.com": "당근마켓", "yes24.com": "예스24", "sktelecom.com": "SK텔레콤",
    "sktmembership.co.kr": "T멤버십", "ahnlab.com": "안랩 백신 업데이트", "gugak.go.kr": "국립국악원",
    "kr-weathernews.com": "웨더뉴스 날씨",
    # AI·개발
    "anthropic.com": "Claude (Anthropic)", "claude.ai": "Claude 웹·앱", "claudeusercontent.com": "Claude 첨부·결과물",
    "openai.com": "OpenAI (ChatGPT)", "chatgpt.com": "ChatGPT", "z.ai": "Z.ai (GLM AI)", "deepseek.com": "DeepSeek AI",
    "openrouter.ai": "OpenRouter AI 중계", "nousresearch.com": "Nous Research AI", "opencode.ai": "OpenCode 코딩 도구",
    "replit.com": "Replit", "replit.dev": "Replit 개발 앱", "replit.app": "Replit으로 만든 웹앱",
    "jsdelivr.net": "jsDelivr (웹페이지 공용 라이브러리)", "aside.com": "Aside 브라우저", "asidehq.com": "Aside 브라우저 동기화",
    "browser-intake-us5-datadoghq.com": "앱 모니터링 (Datadog)", "github.com": "GitHub", "githubusercontent.com": "GitHub 파일 다운로드",
    "github.io": "GitHub Pages 웹사이트", "docker.com": "Docker", "turso.io": "Turso 데이터베이스", "run.app": "Google Cloud Run 앱",
    "vscode-cdn.net": "VS Code 업데이트·확장", "desktopcommander.app": "Desktop Commander", "cmux.com": "cmux 터미널",
    "cmux.dev": "cmux 터미널", "obsidian.md": "Obsidian 동기화·업데이트", "notion.com": "Notion", "slack.com": "Slack",
    "slackb.com": "Slack 사용 통계", "grafana.com": "Grafana", "onorca.dev": "Orca",
    # 빅테크
    "google.com": "Google", "googleapis.com": "Google 앱 서버 (API)", "gstatic.com": "Google 정적 파일",
    "googleusercontent.com": "Google 사용자 콘텐츠", "gmail.com": "Gmail", "dns.google": "Google DNS (암호화 DNS)",
    "youtube.com": "YouTube", "googlevideo.com": "YouTube 영상 재생", "ytimg.com": "YouTube 썸네일",
    "connectivitycheck.gstatic.com": "안드로이드 인터넷 연결 확인",
    "apple.com": "Apple", "icloud.com": "iCloud", "mzstatic.com": "App Store 이미지·앱", "push.apple.com": "Apple 푸시 알림",
    "microsoft.com": "Microsoft", "office.com": "Microsoft Office", "ecs.office.com": "Office 앱 설정·기능 업데이트",
    "live.com": "Microsoft 계정·Outlook", "bing.com": "Bing", "clarity.ms": "Microsoft Clarity 사이트 분석",
    "samsung.com": "삼성 서비스", "samsungcloud.com": "삼성 클라우드", "samsungapis.com": "삼성 앱 서버",
    "samsungapps.com": "Galaxy Store", "mi.com": "샤오미 서비스", "ninebot.com": "나인봇 (킥보드) 앱",
    "tplinkcloud.com": "TP-Link 공유기·카메라 클라우드",
    "facebook.com": "Facebook", "facebook.net": "Facebook SDK·광고", "fbcdn.net": "Facebook 이미지·영상",
    "instagram.com": "Instagram", "cdninstagram.com": "Instagram 이미지·영상", "x.com": "X (트위터)", "twimg.com": "X 이미지",
    "linkedin.com": "LinkedIn", "discord.com": "Discord", "discordapp.com": "Discord", "discord.gg": "Discord 초대 링크",
    "netflix.com": "Netflix", "aliexpress.com": "AliExpress 쇼핑", "aliexpress-media.com": "AliExpress 이미지",
    "terabox.com": "TeraBox 클라우드 저장소", "epicgames.com": "Epic Games", "epicgames.dev": "Epic Games 게임 서버",
    "unrealengine.com": "Unreal Engine", "supercell.com": "Supercell 게임", "unity3d.com": "Unity 게임 엔진·광고",
    # 브라우저·보안
    "opera.com": "Opera 브라우저", "speeddials.opera.com": "Opera 새 탭 바로가기 타일",
    "opera-api.com": "Opera 브라우저 서버", "opera-api2.com": "Opera 브라우저 서버",
    "mozilla.org": "Firefox", "mozilla.net": "Firefox 업데이트", "adblockplus.org": "Adblock Plus 필터 업데이트",
    "mcafee.com": "McAfee 백신", "hcaptcha.com": "hCaptcha 사람 확인",
    # 인프라·CDN (어느 앱이든 쓰는 공용 서버)
    "cloudflare.com": "Cloudflare (여러 사이트 공용)", "cloudflare-dns.com": "Cloudflare DNS (암호화 DNS)",
    "fastly-edge.com": "Fastly CDN (여러 사이트 공용)", "aliyuncs.com": "알리바바 클라우드 (중국 앱 서버)",
    "bcebos.com": "바이두 클라우드 저장소", "volces.com": "바이트댄스 클라우드", "amazonaws.com": "AWS (여러 앱 공용)",
    "akamaized.net": "Akamai CDN (여러 사이트 공용)", "tailscale.com": "Tailscale (이 VPN)",
    "in-addr.arpa": "IP → 이름 역조회", "ip6.arpa": "IP → 이름 역조회",
    # 광고·분석 SDK (앱 안에 들어 있는 것)
    "doubleclick.net": "Google 광고", "google-analytics.com": "Google 방문 통계", "applovin.com": "앱 광고 (AppLovin)",
    "pangle.io": "앱 광고 (틱톡 Pangle)", "tiktokpangle.us": "앱 광고 (틱톡 Pangle)", "i18n-pglstatp.com": "앱 광고 (틱톡 Pangle)",
    "moloco.com": "앱 광고 (Moloco)", "inmobi.com": "앱 광고 (InMobi)", "vungle.com": "앱 광고 (Vungle)",
    "inner-active.mobi": "앱 광고 (DT Exchange)", "mentamob.com": "앱 광고", "advlion.com": "앱 광고", "admaster.cc": "광고 측정",
    "adjoe.zone": "앱 광고 (adjoe)", "rayjump.com": "앱 광고 (Mintegral)", "vervegroupinc.net": "앱 광고 (Verve)",
    "planetad.co.kr": "앱 광고", "appsflyersdk.com": "앱 설치 경로 분석 (AppsFlyer)", "adbrix.io": "앱 분석 (Adbrix)",
    "airbridge.io": "앱 설치 경로 분석 (Airbridge)", "braze.com": "앱 푸시·마케팅 (Braze)", "acecounter.com": "방문 통계",
    "amplitude.com": "앱 사용 통계 (Amplitude)", "posthog.com": "앱 사용 통계 (PostHog)", "exp-tas.com": "VS Code 실험 기능 설정",
    "launchdarkly.com": "앱 기능 켜고 끄기 (LaunchDarkly)", "featureassets.org": "앱 기능 설정 (Statsig)",
    "sentry.io": "앱 오류 보고 (Sentry)", "bugsnag.com": "앱 오류 보고 (Bugsnag)", "crashlytics.com": "앱 오류 보고 (Firebase)",
    "datadoghq.com": "앱 모니터링 (Datadog)", "splunkcloud.com": "앱 모니터링 (Splunk)",
    # 2026-11-06 추가 (godam 기록 중 설명 없던 것)
    "splashtop.com": "Splashtop 원격 접속", "gvt1.com": "Chrome·Google 앱 업데이트 다운로드", "digicert.com": "인증서 유효성 확인",
    "safebrowsing.apple": "Safari 위험 사이트 확인", "cdn-apple.com": "Apple 업데이트·파일", "taobao.com": "타오바오 쇼핑",
    "163.com": "넷이즈 (중국 포털·게임)", "googlesyndication.com": "Google 광고", "googletagmanager.com": "Google 태그 관리 (사이트 통계)",
    "scorecardresearch.com": "방문 통계 (comScore)", "intercom.io": "웹사이트 상담 채팅", "intercomcdn.com": "웹사이트 상담 채팅",
    "ipify.org": "내 공인 IP 확인", "ampproject.org": "Google AMP 웹페이지", "slack-edge.com": "Slack 파일·이미지",
    "slackhq.com": "Slack", "reddit.com": "Reddit", "redditstatic.com": "Reddit 이미지·파일", "hex.tech": "Hex 데이터 분석",
    "gmarket.co.kr": "G마켓", "tworlddirect.com": "T다이렉트샵 (SKT)", "upbit.com": "업비트 거래소", "buzzvil.com": "리워드 광고 (버즈빌)",
    "revenuecat.com": "앱 구독 결제 관리", "pangle-b.io": "앱 광고 (틱톡 Pangle)", "konacard.co.kr": "코나카드",
    "mapbox.com": "지도 (Mapbox)", "onetrust.io": "쿠키 동의 창", "cookielaw.org": "쿠키 동의 창", "appiersig.com": "앱 광고 (Appier)",
    "appier.net": "앱 광고 (Appier)", "hubspot.com": "HubSpot 마케팅", "hs-scripts.com": "HubSpot 마케팅", "hs-analytics.net": "HubSpot 방문 통계",
    "hsadspixel.net": "HubSpot 광고 측정", "optimizely.com": "웹사이트 A/B 실험", "speedcurve.com": "웹사이트 속도 측정",
    "npmjs.org": "npm 패키지 다운로드", "dfinery.io": "앱 분석 (디파이너리)", "discord.media": "Discord 이미지·영상",
    "discordapp.net": "Discord 이미지·영상", "fengkongcloud.com": "중국 앱 부정사용 방지 SDK", "toast.com": "NHN 클라우드",
    "twitter.com": "X (트위터)", "t.co": "X 단축 링크", "ads-twitter.com": "X 광고 측정", "samsungconsent.com": "삼성 개인정보 동의",
    "samsunghealth.com": "삼성 헬스", "samsungcal.com": "삼성 캘린더", "gcp-karroter.net": "당근마켓 서버",
    "weather.com": "날씨 (The Weather Company)", "telemetrydeck.com": "앱 사용 통계 (TelemetryDeck)", "google.co.kr": "Google",
    "jscrambler.com": "웹사이트 보안 스크립트", "speedtest.net": "인터넷 속도 측정", "coupang.com": "쿠팡", "coupangcdn.com": "쿠팡 이미지",
    "contentsquare.net": "웹사이트 행동 분석", "demandbase.com": "B2B 마케팅 추적", "company-target.com": "B2B 마케팅 추적",
    "tremorhub.com": "동영상 광고", "pardot.com": "Salesforce 마케팅", "notionusercontent.com": "Notion 첨부 파일",
    "alibabausercontent.com": "알리바바 이미지·파일", "lazada.sg": "Lazada 쇼핑", "figma.com": "Figma", "asana.com": "Asana",
    "monday.com": "monday.com", "pagerduty.com": "PagerDuty", "zoom.us": "Zoom", "meetup.com": "Meetup", "lu.ma": "Luma 행사",
    "shinhansec.com": "신한투자증권", "wooribank.com": "우리은행", "githubassets.com": "GitHub 화면 파일", "licdn.com": "LinkedIn 이미지·파일",
    "statsigapi.net": "앱 기능 설정 (Statsig)", "awstrack.me": "메일 링크 클릭 추적 (AWS)", "huggingface.co": "Hugging Face AI 모델",
    "grok.com": "Grok AI (xAI)", "oaiusercontent.com": "ChatGPT 첨부·결과물", "claude.com": "Claude", "daumcdn.net": "다음 이미지·파일",
    "appboycdn.com": "앱 푸시·마케팅 (Braze)", "braze-images.com": "앱 푸시·마케팅 (Braze)", "xiaomi.com": "샤오미 서비스",
    "xiaomi.net": "샤오미 서비스", "mi-img.com": "샤오미 이미지", "miui.com": "샤오미 MIUI", "gos-gsp.io": "삼성 게임 최적화 서비스",
    "appcenter.ms": "앱 오류·사용 통계 (Microsoft)", "cloudflareinsights.com": "Cloudflare 방문 통계", "substack.com": "Substack 뉴스레터",
    "substackcdn.com": "Substack 이미지", "helpshift.com": "앱 고객 지원 채팅", "syrup.co.kr": "시럽 (SK플래닛)",
    "stack-auth.com": "로그인 서비스 (Stack Auth)", "sanity.io": "웹사이트 콘텐츠 관리", "scene7.com": "Adobe 이미지 서버",
    "abr.ge": "앱 링크 (Airbridge)", "adison.co": "리워드 광고 (애디슨)", "admixer.co.kr": "앱 광고 (애드믹서)",
    "ketchcdn.com": "쿠키 동의 창", "ketchjs.com": "쿠키 동의 창", "antigravity-unleash.goog": "Google Antigravity 기능 설정",
    "ts.net": "Tailscale 내부 기기",
    # 추정: 정체가 확인되지 않아 기록(기기·주기·함께 나온 도메인)으로만 짐작한 것. 확인되면 "추정:" 을 떼거나 고친다.
    "firwinds.site": "추정: 광고 많은 앱의 서버 확인",       # S24, 15분마다, TeraBox·광고 SDK 와 함께 (11-06)
    "cr-relay.com": "추정: 웹페이지 광고·추적 스크립트",     # Mac Safari 웹페이지 보던 중 한 번 (11-06)
    "mczbf.com": "추정: 웹페이지 광고·추적 스크립트",        # 위와 같은 시각, CloudFront (11-06)
}


def purpose(host):
    """'speeddials.opera.com' → 'Opera 새 탭 바로가기 타일'. 'x.com [tls]' 처럼 꼬리표가 붙어 있어도 된다."""
    if not host:
        return None
    h = str(host).split(" [", 1)[0].strip().lower().rstrip(".")
    if h and "." not in h and not h.isdigit():
        return "내부 기기 이름 조회"                      # 'godam' 처럼 점 없는 이름 (MagicDNS·공유기)
    parts = h.split(".")
    for i in range(len(parts) - 1):                      # 가장 긴 이름부터 → 가장 구체적인 설명
        hit = PURPOSE.get(".".join(parts[i:]))
        if hit:
            return hit
    return None


def base_domain(h):
    """'a.b.example.co.kr' → 'example.co.kr', 'x.y.example.com' → 'example.com' (표에 넣을 이름 후보)."""
    parts = h.split(".")
    return ".".join(parts[-3:] if len(parts) > 2 and parts[-2] in ("co", "or", "go", "ne", "ac", "com") else parts[-2:])


def unknown(lines):
    """eve.json 줄들 → 설명이 없는 도메인 {기본 도메인: 횟수}. IP 로만 접속한 것은 뺀다."""
    import collections, ipaddress, json
    c = collections.Counter()
    for line in lines:
        if '"sni"' not in line and '"rrname"' not in line and '"hostname"' not in line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        dns = e.get("dns") or {}
        h = ((e.get("tls") or {}).get("sni") or (e.get("http") or {}).get("hostname") or dns.get("rrname")
             or (dns.get("queries") or [{}])[0].get("rrname"))
        if not isinstance(h, str) or not h:
            continue
        h = h.lower().rstrip(".")
        try:
            ipaddress.ip_address(h); continue
        except ValueError:
            pass
        if not purpose(h):
            c[base_domain(h)] += 1
    return c


if __name__ == "__main__":
    # exitguardctl purpose-unknown [줄 수]: 최근 eve.json 에서 설명 없는 도메인 상위 50 (표에 추가할 후보)
    import collections, sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    with open("/var/log/suricata/eve.json", errors="replace") as f:
        tail = collections.deque(f, maxlen=n)
    for dom, cnt in unknown(tail).most_common(50):
        print(f"{cnt:7d}  {dom}")
