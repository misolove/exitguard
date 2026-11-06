"""목적지 이름(SNI·DNS·HTTP 호스트) → 짧은 한국어 용도 설명. 사람이 고른 고정 표 (AI·네트워크 조회 없음).

규칙: 호스트가 표의 이름과 같거나 그 하위 도메인이면 맞음. 여러 개가 맞으면 가장 긴(구체적인) 것.
표에 없으면 None (화면은 용도를 생략). 새 서비스는 아래 표에 한 줄 추가.
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
}


def purpose(host):
    """'speeddials.opera.com' → 'Opera 새 탭 바로가기 타일'. 'x.com [tls]' 처럼 꼬리표가 붙어 있어도 된다."""
    if not host:
        return None
    h = str(host).split(" [", 1)[0].strip().lower().rstrip(".")
    parts = h.split(".")
    for i in range(len(parts) - 1):                      # 가장 긴 이름부터 → 가장 구체적인 설명
        hit = PURPOSE.get(".".join(parts[i:]))
        if hit:
            return hit
    return None
