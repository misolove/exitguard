#!/bin/sh
# DB-IP IP to Country Lite (CC BY 4.0) 를 받아 웹 지구본용 GeoIP 파일을 바꾼다.
# 이번 달 파일이 아직 없으면 지난달 파일. 검증에 실패하면 기존 파일을 그대로 둔다.
# 웹 서비스는 파일이 바뀐 것을 1분 안에 알아채 다시 읽는다 (재시작 불필요).
set -eu
DB=${EXITGUARD_GEOIP_DB:-/var/lib/exitguard/dbip-country-lite.csv.gz}
TMP="$DB.tmp"
install -d -m 755 "$(dirname "$DB")"
trap 'rm -f "$TMP"' EXIT
for month in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m)"; do
  if curl -fsSL --max-time 300 -o "$TMP" "https://download.db-ip.com/free/dbip-country-lite-$month.csv.gz"; then
    break
  fi
  rm -f "$TMP"
done
[ -s "$TMP" ] || { echo "GeoIP 다운로드 실패, 기존 파일 유지" >&2; exit 1; }
gzip -t "$TMP" || { echo "GeoIP 파일 손상, 기존 파일 유지" >&2; exit 1; }
rows=$(gzip -dc "$TMP" | wc -l)
[ "$rows" -ge 100000 ] || { echo "GeoIP 행 수 이상($rows), 기존 파일 유지" >&2; exit 1; }
chmod 644 "$TMP" && mv "$TMP" "$DB"
echo "GeoIP 갱신: $month, $rows 행"
