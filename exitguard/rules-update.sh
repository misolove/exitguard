#!/bin/bash
# ET Open 룰 + ExitGuard local.rules 를 받아 /var/lib/suricata/rules/suricata.rules 로 병합 후 리로드
set -e
suricata-update --no-test --local /etc/exitguard/local.rules -q || suricata-update --local /etc/exitguard/local.rules
# 룰 검증
if suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules --set vars.address-groups.HOME_NET="[100.64.0.0/10,fd7a:115c:a1e0::/48]" >/tmp/exitguard-rules-test.log 2>&1; then
  systemctl kill -s USR2 suricata 2>/dev/null || systemctl restart suricata
  echo "rules updated & reloaded"
else
  echo "rule test FAILED, not reloading. see /tmp/exitguard-rules-test.log" >&2
  exit 1
fi
