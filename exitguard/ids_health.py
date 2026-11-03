#!/usr/bin/env python3
"""Suricata 탐지 상태 점검 (rules-update.sh 가 규칙 재적재 전후에 호출).

2026-11-02 사고: HOME_NET 을 시작 옵션(--set)으로만 tailnet 으로 주고 suricata.yaml 은 기본값(사설망)이었다.
규칙 재적재(USR2) 뒤 YAML 값으로 돌아가 $HOME_NET 을 쓰는 거의 모든 규칙(ET·local.rules)이 이틀간 걸리지 않았다.
사용: ids_health.py check-yaml            suricata.yaml 의 HOME_NET 이 tailnet 이면 0, 아니면 1
      ids_health.py wait-reload <epoch>    그 시각 이후 재적재가 끝나고 규칙이 실려 있으면 0, 아니면 HIGH 알림 후 1
"""
import json, os, re, sys, time
from datetime import datetime

YAML = os.environ.get("EXITGUARD_SURICATA_YAML", "/etc/suricata/suricata.yaml")
EVE = os.environ.get("EXITGUARD_EVE", "/var/log/suricata/eve.json")
TAILNET = "100.64.0.0/10"
MIN_RULES = 1000


def yaml_home_net(path=YAML):
    """주석이 아닌 첫 HOME_NET: 값 (따옴표 제외). 없으면 None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r'^\s*HOME_NET:\s*"?([^"#\n]*)"?', line)
                if m:
                    return m.group(1).strip()
    except OSError:
        return None
    return None


def latest_engine(path=EVE, tail=8 * 1024 * 1024):
    """eve.json 끝부분에서 가장 최근 stats 의 detect.engines[0] (없으면 None)."""
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.path.getsize(path) - tail))
            lines = f.read().splitlines()
    except OSError:
        return None
    for raw in reversed(lines):
        if b'"event_type":"stats"' not in raw:
            continue
        try:
            engines = json.loads(raw)["stats"]["detect"]["engines"]
        except (ValueError, KeyError, TypeError):
            continue
        if engines:
            return engines[0]
    return None


def reload_ok(engine, since):
    """(완료 여부, 설명). 완료 = since 이후 재적재, 규칙 MIN_RULES 개 이상, 실패 0."""
    if not engine:
        return False, "Suricata 통계(stats) 없음"
    try:
        at = datetime.fromisoformat(engine["last_reload"]).timestamp()
    except (KeyError, ValueError, TypeError):
        return False, "재적재 시각 없음"
    if at < since - 1:
        return False, "재적재가 아직 반영되지 않음"
    loaded, failed = engine.get("rules_loaded", 0), engine.get("rules_failed", 0)
    if failed or loaded < MIN_RULES:
        return False, f"규칙 적재 이상: 성공 {loaded}, 실패 {failed}"
    return True, f"규칙 {loaded}개 적재"


def alert(title):
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    try:
        from common import Notifier, load_config
        Notifier(load_config()).emit("HIGH", "ids-health", title, dedupe_key="ids-health:" + title)
    except Exception as e:   # 알림 실패가 점검 결과를 가리지 않게
        print(f"알림 전송 실패: {e}", file=sys.stderr)


def main(argv):
    if argv[1:2] == ["check-yaml"]:
        value = yaml_home_net()
        ok = bool(value) and TAILNET in value
        print(f"suricata.yaml HOME_NET = {value!r}" + ("" if ok else f" ({TAILNET} 없음)"))
        return 0 if ok else 1
    if argv[1:2] == ["wait-reload"] and len(argv) == 3:
        since, end, msg = float(argv[2]), time.time() + 120, ""
        while time.time() < end:
            ok, msg = reload_ok(latest_engine(), since)
            if ok:
                print("Suricata 탐지 정상: " + msg)
                return 0
            time.sleep(5)
        alert("Suricata 규칙 재적재 확인 실패: " + msg)
        print("Suricata 탐지 확인 실패: " + msg, file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
