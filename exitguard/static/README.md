# static

웹 대시보드(`--web`)가 `/static/` 으로 내보내는 파일. 실행 중 외부(CDN·지도 타일)에서 불러오는 것은 없다.

| 파일 | 내용 | 출처·라이선스 |
|---|---|---|
| `viz.js` | 시계열·등급 막대·도넛·알림 묶음·지구본 (인라인 SVG, 의존성 없음) | 이 레포 (MIT) |
| `parts.html` | 각 부품을 `/api/snapshot` 에 붙인 견본 페이지 (`/static/parts.html`) | 이 레포 (MIT) |
| `countries-110m.json` | 세계 지도 TopoJSON (1:110m) | [world-atlas](https://github.com/topojson/world-atlas) 2.0.2, ISC © Mike Bostock. 원 데이터 Natural Earth (public domain) |
