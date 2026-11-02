#!/bin/bash
set -u
[ "$(id -u)" = 0 ] || { echo "sudo 로 실행하세요"; exit 1; }
systemctl disable --now exitguard-watch exitguard-report.timer exitguard-rules.timer exitguard-nft 2>/dev/null
nft delete table inet exitguard 2>/dev/null
rm -f /etc/systemd/system/exitguard-* /etc/systemd/system/suricata.service.d/exitguard.conf
systemctl daemon-reload
rm -rf /usr/local/lib/exitguard /usr/local/bin/exitguardctl
echo "설정/로그는 보존됨: /etc/exitguard /var/lib/exitguard /var/log/exitguard"
echo "Suricata 제거: apt-get remove suricata   |  exit node 중지: tailscale set --advertise-exit-node=false"
