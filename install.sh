#!/bin/bash
# ExitGuard 설치: Tailscale exit node + Suricata IDS + 탐지/차단 데몬
# 사용: sudo ./install.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "sudo 로 실행하세요: sudo $0"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
IFACE=tailscale0
HOME_NET='[100.64.0.0/10,fd7a:115c:a1e0::/48]'
WAN=$(ip route show default | awk '/default/ {print $5; exit}')
step() { echo; echo "▶ $*"; }

step "1/8 패키지 설치 (suricata, suricata-update, conntrack, jq, tcpdump)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq suricata suricata-update conntrack jq tcpdump nftables ethtool >/dev/null
OVR=/etc/systemd/system/suricata.service.d/exitguard.conf
OVR_BEFORE=$(md5sum $OVR 2>/dev/null | cut -d' ' -f1)

step "2/8 IP 포워딩 + exit node 성능 튜닝(GRO forwarding)"
install -m 644 "$SRC/etc/99-tailscale-forward.conf" /etc/sysctl.d/99-tailscale-forward.conf
sysctl -q --system >/dev/null
# 모든 물리 인터페이스(유선/무선)에 GRO forwarding 튜닝 적용 — 기본 경로가 바뀌어도 유효
mkdir -p /etc/networkd-dispatcher/routable.d
cat > /etc/networkd-dispatcher/routable.d/50-tailscale <<'NDS'
#!/bin/sh
for i in /sys/class/net/*; do
  n=$(basename $i)
  case "$n" in lo|tailscale*|docker*|veth*|br-*|virbr*) continue;; esac
  ethtool -K "$n" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
done
NDS
chmod 755 /etc/networkd-dispatcher/routable.d/50-tailscale
/etc/networkd-dispatcher/routable.d/50-tailscale

step "3/8 ExitGuard 파일 배치"
mkdir -p /etc/exitguard /usr/local/lib/exitguard /var/lib/exitguard /var/log/exitguard
if [ -f /etc/exitguard/config.json ]; then
  # 기존 설정 보존 + 새 기본 키만 병합
  jq -s '.[0] * .[1]' "$SRC/etc/config.json" /etc/exitguard/config.json > /etc/exitguard/config.json.new && mv /etc/exitguard/config.json.new /etc/exitguard/config.json
  chmod 640 /etc/exitguard/config.json
else
  install -m 640 "$SRC/etc/config.json" /etc/exitguard/config.json
fi
install -m 644 "$SRC/etc/nftables-exitguard.conf" "$SRC/etc/nftables-exitguard-min.conf" /etc/exitguard/
install -m 644 "$SRC/etc/local.rules" /etc/exitguard/local.rules
install -m 755 "$SRC"/exitguard/*.py "$SRC"/exitguard/rules-update.sh /usr/local/lib/exitguard/
install -m 755 "$SRC/bin/exitguardctl" /usr/local/bin/exitguardctl
ln -sf /usr/local/lib/exitguard/dash.py /usr/local/bin/exitguard-top
install -m 644 "$SRC"/systemd/*.service "$SRC"/systemd/*.timer /etc/systemd/system/

step "4/8 nftables 차단 테이블 로드"
if nft -f /etc/exitguard/nftables-exitguard.conf; then
  echo "  full ruleset (with per-client counters) loaded"
else
  echo "  counter set 미지원 → 최소 룰셋으로 폴백"
  nft -f /etc/exitguard/nftables-exitguard-min.conf
fi

step "5/8 Suricata 설정 (af-packet on $IFACE, HOME_NET=tailnet)"
mkdir -p /etc/systemd/system/suricata.service.d
TYPE=$(systemctl show suricata -p Type --value 2>/dev/null || echo forking)
DAEMON=""; [ "$TYPE" = forking ] && DAEMON="-D"
cat > /etc/systemd/system/suricata.service.d/exitguard.conf <<SUR
[Service]
ExecStart=
ExecStart=/usr/bin/suricata $DAEMON -c /etc/suricata/suricata.yaml --af-packet=$IFACE --pidfile /run/suricata.pid --set vars.address-groups.HOME_NET=$HOME_NET --set af-packet.0.interface=$IFACE --set af-packet.0.cluster-id=99 --set af-packet.0.threads=4 --set af-packet.0.checksum-checks=no --set stream.checksum-validation=no
Restart=always
RestartSec=10
SUR
# Debian 기본 unit 이 ExecStartPre/ReloadPropagatedFrom 등을 쓰더라도 위 ExecStart 만 교체됨
sed -i 's/^\(\s*\)- interface: eth0/\1- interface: '"$IFACE"'/' /etc/suricata/suricata.yaml
sed -i -E 's/^(\s*#?\s*community-id:).*/\1 true/' /etc/suricata/suricata.yaml

step "6/8 Suricata 룰 다운로드 (ET Open) + ExitGuard 룰 병합"
suricata-update update-sources -q 2>/dev/null || true
suricata-update --no-test --local /etc/exitguard/local.rules -q || suricata-update --local /etc/exitguard/local.rules
echo "  설정 검증..."
suricata -T -c /etc/suricata/suricata.yaml --set vars.address-groups.HOME_NET="$HOME_NET" --af-packet=$IFACE >/tmp/exitguard-suricata-test.log 2>&1 \
  && echo "  OK" || { echo "  Suricata 설정 테스트 실패: /tmp/exitguard-suricata-test.log"; tail -20 /tmp/exitguard-suricata-test.log; exit 1; }

step "7/8 서비스 활성화"
systemctl daemon-reload
systemctl enable --now exitguard-nft.service
if systemctl is-active --quiet suricata && [ "$OVR_BEFORE" = "$(md5sum $OVR | cut -d' ' -f1)" ]; then
  echo "  Suricata 실행 중 + 설정 불변 → 룰만 무중단 리로드"
  systemctl kill -s USR2 suricata
else
  systemctl enable --now suricata
  systemctl restart suricata
fi
sleep 3
systemctl enable --now exitguard-watch.service exitguard-report.timer exitguard-rules.timer
systemctl restart exitguard-watch.service
systemctl --no-pager --lines=0 status suricata exitguard-watch | grep -E 'Active|●' || true

step "8/8 Tailscale exit node 광고"
tailscale set --advertise-exit-node
echo "  광고 완료. 관리 콘솔(https://login.tailscale.com/admin/machines)에서 $(hostname) 의 'Exit node' 를 승인해야 합니다."
echo "  (Auto-approvers 정책이 있으면 자동 승인됨)"

echo
echo "=============================================================="
echo " 설치 완료"
echo "   대시보드:      exitguard-top   (sudo exitguard-top 이면 조치 가능)"
echo "   상태:          exitguardctl status"
echo "   실시간 알림:   exitguardctl watch"
echo "   클라이언트:    exitguardctl clients"
echo "   리포트:        exitguardctl report"
echo "   설정:          /etc/exitguard/config.json  (webhook/telegram 입력 가능)"
echo "   Suricata 로그: /var/log/suricata/eve.json, fast.log"
echo "   UFW 상태:      $(ufw status 2>/dev/null | head -1)"
echo "=============================================================="
