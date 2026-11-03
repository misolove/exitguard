#!/bin/sh
# 개발 PC 에서 설치된 exit node 로 대시보드·감시 코드만 갱신 (텍스트판 + 웹판).
# 사용: bin/deploy.sh <ssh 대상>          예) bin/deploy.sh user@exit-node
#   1) exitguard/ 와 systemd/exitguard-{web,geoip}.* 를 대상의 ~/exitguard-staging 으로 복사
#   2) 대상에서 sudo 한 번: 기존 /usr/local/lib/exitguard 백업 → 설치 → 웹 서비스 켜기/재시작
#      GeoIP 파일이 있으면 월간 갱신 타이머(exitguard-geoip.timer)도 켠다
#      watch.py·common.py 가 바뀌었을 때만 exitguard-watch 재시작
# Suricata·nftables 설정은 건드리지 않는다 (처음 설치는 install.sh).
set -eu
[ $# -eq 1 ] || { echo "사용: $0 <ssh 대상>" >&2; exit 2; }
DEST=$1
SRC=$(cd "$(dirname "$0")/.." && pwd)

tar -C "$SRC" -czf - --exclude='__pycache__' exitguard systemd/exitguard-web.service systemd/exitguard-geoip.service systemd/exitguard-geoip.timer \
  | ssh "$DEST" 'rm -rf ~/exitguard-staging && mkdir -p ~/exitguard-staging && tar -C ~/exitguard-staging -xzf -'

ssh -t "$DEST" 'sudo sh -eu -c '"'"'
S=$1; L=/usr/local/lib/exitguard
B=/var/backups/exitguard/$(date +%Y%m%d-%H%M%S)
mkdir -p "$B" && cp -a "$L" "$B/" && echo "백업: $B"
restart_watch=0
for f in watch.py common.py; do cmp -s "$S/exitguard/$f" "$L/$f" || restart_watch=1; done
install -m 755 "$S"/exitguard/*.py "$S"/exitguard/rules-update.sh "$S"/exitguard/geoip-update.sh "$L/"
install -d "$L/static" && install -m 644 "$S"/exitguard/static/* "$L/static/"
install -m 644 "$S"/systemd/exitguard-web.service "$S"/systemd/exitguard-geoip.service "$S"/systemd/exitguard-geoip.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable exitguard-web.service >/dev/null 2>&1
systemctl restart exitguard-web.service
# GeoIP 를 쓰는 경우(파일이 있을 때)만 월간 갱신 타이머를 켠다
[ -f /var/lib/exitguard/dbip-country-lite.csv.gz ] && systemctl enable --now exitguard-geoip.timer >/dev/null 2>&1 && echo "GeoIP 월간 갱신 타이머 켜짐"
[ "$restart_watch" = 1 ] && systemctl restart exitguard-watch.service && echo "exitguard-watch 재시작"
sleep 2; systemctl --no-pager --lines=3 status exitguard-web.service | sed -n "1,3p;/ExitGuard web/p"
'"'"' sh "$HOME/exitguard-staging"'
