#!/bin/bash
# ET Open 룰 + ExitGuard local.rules 를 받아 /var/lib/suricata/rules/suricata.rules 로 병합 후 리로드
# 리로드 뒤 탐지 상태를 확인한다 (실패하면 ids_health.py 가 HIGH 알림을 보내고 이 스크립트도 실패로 끝남)
set -e
H=/usr/local/lib/exitguard/ids_health.py
suricata-update --no-test --local /etc/exitguard/local.rules -q || suricata-update --local /etc/exitguard/local.rules
# 룰 검증
if suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules --set vars.address-groups.HOME_NET="[100.64.0.0/10,fd7a:115c:a1e0::/48]" >/tmp/exitguard-rules-test.log 2>&1; then
  since=$(date +%s)
  # 실행 중 재적재(USR2)는 시작 옵션 --set 을 다시 적용하지 않는다. YAML 의 HOME_NET 이 tailnet 일 때만 재적재,
  # 아니면 재시작해서 --set 이 적용되게 한다 (2026-11-02 탐지 중단 사고)
  if python3 "$H" check-yaml; then
    systemctl kill -s USR2 suricata 2>/dev/null || systemctl restart suricata
  else
    echo "suricata.yaml 의 HOME_NET 이 tailnet 이 아님 → 재적재 대신 재시작" >&2
    systemctl restart suricata
  fi
  python3 "$H" wait-reload "$since"
  echo "rules updated & reloaded"
else
  echo "rule test FAILED, not reloading. see /tmp/exitguard-rules-test.log" >&2
  exit 1
fi
