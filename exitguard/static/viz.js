/* ExitGuard 웹 대시보드 시각화 부품. 외부 라이브러리 없이 인라인 SVG 만 쓴다.
 * 모든 함수는 <svg> 요소를 받아 내용을 다시 그리고, 데이터는 /api/snapshot 의 필드를 그대로 받는다.
 *   EGViz.line(svg, s.series)          기기별 트래픽 시계열
 *   EGViz.levelBars(svg, s.alerts_24h) 24h 등급별 알림 막대
 *   EGViz.donut(svg, s.protos)         app_proto 바이트 비율
 *   EGViz.alertGroups(box, s.alert_groups)  같은 알림을 한 줄로 접은 목록 (div 에 그림)
 *   const g = EGViz.globe(svg, topology); g.update(s.geo)   드래그 회전·휠/핀치 확대 지구본
 * 텍스트는 모두 textContent 로 넣는다 (innerHTML 금지).
 */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const LEVEL_COLOR = { CRITICAL: "#cf222e", HIGH: "#e5534b", MEDIUM: "#d29922", LOW: "#58a6ff", INFO: "#8b949e" };
  const PALETTE = ["#58a6ff", "#f0a23b", "#3fb950", "#bc8cff", "#ff7b72", "#39c5cf", "#e3b341", "#8b949e"];

  function s(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = String(text);
    return e;
  }
  function size(svg, w, h) {
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    svg.replaceChildren();
  }
  function human(n) {
    const u = ["B", "K", "M", "G", "T"]; let i = 0; n = n || 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + u[i];
  }
  function color(i) { return PALETTE[i % PALETTE.length]; }

  // ---------------------------------------------------------------- 시계열
  // series = {step: 10, end: epoch초, clients: [{name, ip, bytes: [..최근 N칸..]}]}
  function line(svg, series, opts) {
    const W = 360, H = 160, L = 40, R = 8, T = 10, B = 22;
    size(svg, W, H);
    const cl = (series && series.clients) || [];
    const n = cl.length ? cl[0].bytes.length : 0;
    let max = 1;
    for (const c of cl) for (const v of c.bytes) if (v > max) max = v;
    const x = i => L + (W - L - R) * (n > 1 ? i / (n - 1) : 0);
    const y = v => T + (H - T - B) * (1 - v / max);
    const g = s("g", { "font-size": 10, fill: "currentColor" });
    for (const f of [0, 0.5, 1]) {
      g.append(s("line", { x1: L, x2: W - R, y1: y(max * f), y2: y(max * f), stroke: "currentColor", "stroke-opacity": 0.15 }));
      g.append(s("text", { x: L - 4, y: y(max * f) + 3, "text-anchor": "end", "fill-opacity": 0.7 }, human(max * f)));
    }
    const span = series ? Math.round(n * series.step / 60) : 0;
    g.append(s("text", { x: L, y: H - 6, "fill-opacity": 0.7 }, span ? `-${span}분` : ""));
    g.append(s("text", { x: W - R, y: H - 6, "text-anchor": "end", "fill-opacity": 0.7 }, "지금"));
    svg.append(g);
    cl.forEach((c, k) => {
      if (n < 2) return;
      const d = c.bytes.map((v, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1)).join("");
      svg.append(s("path", { d, fill: "none", stroke: color(k), "stroke-width": 1.8, "stroke-linejoin": "round" }));
    });
    // 범례
    let lx = L;
    cl.forEach((c, k) => {
      const t = s("text", { x: lx + 10, y: T + 4, "font-size": 10, fill: "currentColor" }, c.name);
      svg.append(s("rect", { x: lx, y: T - 3, width: 7, height: 7, fill: color(k), rx: 1 }), t);
      lx += 16 + c.name.length * 6;
    });
    if (!cl.length) svg.append(s("text", { x: W / 2, y: H / 2, "text-anchor": "middle", "font-size": 12, fill: "currentColor", "fill-opacity": 0.6 }, "트래픽 없음"));
  }

  // ---------------------------------------------------------------- 등급별 막대
  function levelBars(svg, counts) {
    const W = 360, H = 64, L = 70, R = 44, rowH = 14;
    size(svg, W, H);
    counts = counts || {};
    const max = Math.max(1, ...LEVELS.map(l => counts[l] || 0));
    LEVELS.forEach((lv, i) => {
      const v = counts[lv] || 0, yy = 2 + i * (rowH + 2);
      const w = (W - L - R) * Math.sqrt(v / max);   // L500 와 H1 이 같이 보이도록 제곱근 축
      svg.append(s("text", { x: L - 6, y: yy + 11, "text-anchor": "end", "font-size": 10, fill: "currentColor" }, lv));
      svg.append(s("rect", { x: L, y: yy, width: Math.max(v ? 2 : 0, w), height: rowH, rx: 2, fill: LEVEL_COLOR[lv] }));
      svg.append(s("text", { x: L + w + 4, y: yy + 11, "font-size": 10, fill: "currentColor" }, v));
    });
  }

  // ---------------------------------------------------------------- 도넛
  // parts = [{label, bytes}]
  function donut(svg, parts) {
    const W = 360, H = 150, cx = 75, cy = 75, r = 60, w = 20;
    size(svg, W, H);
    parts = (parts || []).filter(p => p.bytes > 0);
    const total = parts.reduce((a, p) => a + p.bytes, 0);
    if (!total) {
      svg.append(s("text", { x: W / 2, y: H / 2, "text-anchor": "middle", "font-size": 12, fill: "currentColor", "fill-opacity": 0.6 }, "트래픽 없음"));
      return;
    }
    let a0 = -Math.PI / 2;
    parts.forEach((p, i) => {
      const frac = p.bytes / total, a1 = a0 + frac * Math.PI * 2;
      if (frac >= 0.9999) {
        svg.append(s("circle", { cx, cy, r: r - w / 2, fill: "none", stroke: color(i), "stroke-width": w }));
      } else {
        const big = a1 - a0 > Math.PI ? 1 : 0, ro = r, ri = r - w;
        const P = (rad, a) => `${(cx + rad * Math.cos(a)).toFixed(2)} ${(cy + rad * Math.sin(a)).toFixed(2)}`;
        const d = `M${P(ro, a0)}A${ro} ${ro} 0 ${big} 1 ${P(ro, a1)}L${P(ri, a1)}A${ri} ${ri} 0 ${big} 0 ${P(ri, a0)}Z`;
        svg.append(s("path", { d, fill: color(i) }));
      }
      const ly = 16 + i * 18;
      svg.append(s("rect", { x: 170, y: ly - 9, width: 10, height: 10, rx: 2, fill: color(i) }));
      svg.append(s("text", { x: 186, y: ly, "font-size": 12, fill: "currentColor" },
        `${p.label || "기타"}  ${Math.round(frac * 100)}%  ${human(p.bytes)}`));
      a0 = a1;
    });
    svg.append(s("text", { x: cx, y: cy + 4, "text-anchor": "middle", "font-size": 12, "font-weight": 700, fill: "currentColor" }, human(total)));
  }

  // ---------------------------------------------------------------- 알림 묶음 목록
  // groups = [{level, kind, title, count, last, clients: [이름..], action}]
  function alertGroups(box, groups) {
    box.replaceChildren();
    const div = (cls, text) => { const e = document.createElement("div"); if (cls) e.className = cls; if (text != null) e.textContent = String(text); return e; };
    if (!groups || !groups.length) { box.append(div("empty", "알림 없음")); return; }
    for (const g of groups) {
      const row = div("eg-alert");
      const lv = div("eg-lv", g.level); lv.style.background = LEVEL_COLOR[g.level] || LEVEL_COLOR.INFO;
      const body = div("eg-body");
      body.append(div("eg-title", g.title || ""));
      body.append(div("eg-meta", `${String(g.last || "").slice(11, 19)} · ${(g.clients || []).join(", ")}` + (g.action ? ` · ${g.action}` : "")));
      const cnt = div("eg-count", "×" + g.count);
      row.append(lv, body, cnt);
      box.append(row);
    }
  }

  // ---------------------------------------------------------------- 지구본
  const RAD = Math.PI / 180;

  // TopoJSON (quantized, delta-encoded arcs) → 객체 이름의 [폴리곤[링[[lon,lat]..]..]..]
  function topoPolygons(topo, name) {
    const tf = topo.transform;
    const arcs = topo.arcs.map(arc => {
      let x = 0, y = 0;
      return arc.map(p => { x += p[0]; y += p[1]; return tf ? [x * tf.scale[0] + tf.translate[0], y * tf.scale[1] + tf.translate[1]] : p; });
    });
    const ring = idx => {
      const out = [];
      for (const i of idx) {
        const a = i < 0 ? arcs[~i].slice().reverse() : arcs[i];
        for (let k = out.length ? 1 : 0; k < a.length; k++) out.push(a[k]);
      }
      return out;
    };
    const polys = [];
    const obj = topo.objects[name];
    for (const geom of obj.geometries || [obj]) {
      if (geom.type === "Polygon") polys.push(geom.arcs.map(ring));
      else if (geom.type === "MultiPolygon") for (const p of geom.arcs) polys.push(p.map(ring));
    }
    return polys;
  }

  // 두 점 사이 대원(great circle) 위의 n+1 개 점
  function greatCircle(a, b, n) {
    const v = p => [Math.cos(p[1] * RAD) * Math.cos(p[0] * RAD), Math.cos(p[1] * RAD) * Math.sin(p[0] * RAD), Math.sin(p[1] * RAD)];
    const A = v(a), B = v(b);
    const dot = Math.max(-1, Math.min(1, A[0] * B[0] + A[1] * B[1] + A[2] * B[2]));
    const w = Math.acos(dot), out = [];
    for (let i = 0; i <= n; i++) {
      const t = i / n;
      const k1 = w ? Math.sin((1 - t) * w) / Math.sin(w) : 1 - t, k2 = w ? Math.sin(t * w) / Math.sin(w) : t;
      const x = k1 * A[0] + k2 * B[0], y = k1 * A[1] + k2 * B[1], z = k1 * A[2] + k2 * B[2];
      out.push([Math.atan2(y, x) / RAD, Math.atan2(z, Math.hypot(x, y)) / RAD, t]);
    }
    return { pts: out, angle: w };
  }

  function globe(svg, topology, opts) {
    opts = opts || {};
    const W = opts.width || 360, H = opts.height || 360;
    const base = Math.min(W, H) / 2 - 6;
    const land = topoPolygons(topology, "land");
    const state = { lon: 127, lat: 30, zoom: 1, geo: null, t0: performance.now() };
    const ptrs = new Map();
    // Remember only the previous snapshot; a new alert briefly highlights its destination.
    let alertTimes = null;
    const flashes = new Map();
    let pinch0 = null, raf = 0;

    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.style.touchAction = "none";
    svg.style.cursor = "grab";

    // 정사영(orthographic). [x, y, 보이는지(cos c > 0)]
    function project(lon, lat, lift) {
      const R = base * state.zoom * (lift || 1);
      const l = (lon - state.lon) * RAD, p = lat * RAD, p0 = state.lat * RAD;
      const cosc = Math.sin(p0) * Math.sin(p) + Math.cos(p0) * Math.cos(p) * Math.cos(l);
      const x = R * Math.cos(p) * Math.sin(l);
      const y = -R * (Math.cos(p0) * Math.sin(p) - Math.sin(p0) * Math.cos(p) * Math.cos(l));
      return [W / 2 + x, H / 2 + y, cosc > 0 || (lift > 1 && Math.hypot(x, y) > base * state.zoom)];
    }
    // 뒷면 점은 지평선 원 위로 붙여 채운 다각형이 앞면에서 깨지지 않게 한다
    function ringPath(ring) {
      const R = base * state.zoom;
      let d = "", any = false;
      for (let i = 0; i < ring.length; i++) {
        let [x, y, vis] = project(ring[i][0], ring[i][1]);
        if (vis) any = true;
        else {
          const dx = x - W / 2, dy = y - H / 2, r = Math.hypot(dx, dy) || 1;
          x = W / 2 + dx / r * R; y = H / 2 + dy / r * R;
        }
        d += (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
      }
      return any ? d + "Z" : "";
    }
    // 보이는 구간만 이은 선 (경위선, 호)
    function runs(pts, lift) {
      let d = "", pen = false;
      for (const p of pts) {
        const [x, y, vis] = project(p[0], p[1], lift ? lift(p[2]) : 1);
        if (vis) { d += (pen ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1); pen = true; } else pen = false;
      }
      return d;
    }

    function draw() {
      raf = 0;
      svg.replaceChildren();
      const R = base * state.zoom;
      const clip = "egclip" + (svg.id || "g");
      const defs = s("defs");
      const cp = s("clipPath", { id: clip }); cp.append(s("rect", { x: 0, y: 0, width: W, height: H }));
      const grad = s("radialGradient", { id: clip + "sea", cx: "40%", cy: "35%", r: "75%" });
      grad.append(s("stop", { offset: "0%", "stop-color": "#1d3557" }), s("stop", { offset: "100%", "stop-color": "#0b1526" }));
      defs.append(cp, grad);
      svg.append(defs);
      const root = s("g", { "clip-path": `url(#${clip})` });
      svg.append(root);
      root.append(s("circle", { cx: W / 2, cy: H / 2, r: R, fill: `url(#${clip}sea)` }));

      let grat = "";
      for (let lon = -180; lon < 180; lon += 30) {
        const pts = []; for (let lat = -90; lat <= 90; lat += 3) pts.push([lon, lat]); grat += runs(pts);
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const pts = []; for (let lon = -180; lon <= 180; lon += 3) pts.push([lon, lat]); grat += runs(pts);
      }
      root.append(s("path", { d: grat, fill: "none", stroke: "#58a6ff", "stroke-opacity": 0.12, "stroke-width": 0.6 }));

      let d = "";
      for (const poly of land) for (const ring of poly) d += ringPath(ring);
      root.append(s("path", { d, fill: "#2b4a6f", stroke: "#4f78a8", "stroke-width": 0.5, "fill-rule": "evenodd" }));
      root.append(s("circle", { cx: W / 2, cy: H / 2, r: R, fill: "none", stroke: "#58a6ff", "stroke-opacity": 0.35 }));

      const geo = state.geo;
      if (geo && geo.home) {
        const home = [geo.home.lon, geo.home.lat];
        const pts = geo.points || [];
        const maxB = Math.max(1, ...pts.map(p => p.bytes || 0));
        const t = (performance.now() - state.t0) / 1000;
        for (const p of pts) {
          if (p.lat === geo.home.lat && p.lon === geo.home.lon) continue;
          const gc = greatCircle(home, [p.lon, p.lat], 48);
          const h = 0.04 + 0.12 * gc.angle / Math.PI;   // 멀수록 높이 뜨는 호
          const arc = runs(gc.pts, u => 1 + h * Math.sin(Math.PI * u));
          if (!arc) continue;
          const col = p.blocked ? LEVEL_COLOR.HIGH : "#f0a23b";
          root.append(s("path", { d: arc, fill: "none", stroke: col, "stroke-opacity": 0.35, "stroke-width": 1.2 }));
          // 흐르는 점선: 바이트가 많을수록 빠르게
          const speed = 20 + 60 * Math.sqrt((p.bytes || 0) / maxB);
          root.append(s("path", { d: arc, fill: "none", stroke: col, "stroke-width": 2, "stroke-linecap": "round",
            "stroke-dasharray": "2 14", "stroke-dashoffset": (-t * speed).toFixed(1) }));
        }
        for (const p of pts) {
          const [x, y, vis] = project(p.lon, p.lat);
          if (!vis) continue;
          const r = 2.5 + 6 * Math.sqrt((p.bytes || 0) / maxB);
          const col = p.blocked ? LEVEL_COLOR.HIGH : LEVEL_COLOR[p.level] || "#f0a23b";
          if ((flashes.get(p.ip) || 0) > performance.now()) {
            const alpha = 0.45 + 0.45 * Math.sin(performance.now() / 100);
            root.append(s("circle", { cx: x, cy: y, r: r + 7, fill: "#fff", "fill-opacity": alpha }));
          }
          if (p.blocked || p.level === "HIGH" || p.level === "CRITICAL") {
            const ph = ((performance.now() - state.t0) / 1400) % 1;
            root.append(s("circle", { cx: x, cy: y, r: r + 14 * ph, fill: "none", stroke: col, "stroke-opacity": 1 - ph, "stroke-width": 2 }));
          }
          const dot = s("circle", { cx: x, cy: y, r, fill: col, "fill-opacity": 0.9, stroke: "#0b1526", "stroke-width": 1 });
          dot.append(s("title", {}, `${p.city} · ${p.host || p.ip} · ${human(p.bytes)}${p.blocked ? " · 차단됨" : ""}`));
          root.append(dot);
          const atHome = p.lat === geo.home.lat && p.lon === geo.home.lon;
          if (state.zoom >= 1.6 && !atHome) root.append(s("text", { x: x + r + 3, y: y + 3, "font-size": 10, fill: "#e6edf3" }, p.city));
        }
        const [hx, hy, hv] = project(home[0], home[1]);
        if (hv) {
          root.append(s("circle", { cx: hx, cy: hy, r: 4, fill: "#3fb950", stroke: "#fff", "stroke-width": 1.2 }));
          root.append(s("text", { x: hx + 7, y: hy - 6, "font-size": 10, "font-weight": 700, fill: "#e6edf3" }, geo.home.city));
        }
      }
      if (!opts.static) raf = requestAnimationFrame(draw);   // 점선 흐름·펄스 애니메이션
    }
    function redraw() { if (!raf) raf = requestAnimationFrame(draw); }

    // ---- 조작: 드래그 회전, 휠·핀치 확대, 더블클릭 원위치
    const clampLat = v => Math.max(-85, Math.min(85, v));
    const clampZoom = z => Math.max(1, Math.min(8, z));
    svg.addEventListener("pointerdown", e => { svg.setPointerCapture(e.pointerId); ptrs.set(e.pointerId, [e.clientX, e.clientY]); svg.style.cursor = "grabbing"; });
    svg.addEventListener("pointermove", e => {
      if (!ptrs.has(e.pointerId)) return;
      const prev = ptrs.get(e.pointerId); ptrs.set(e.pointerId, [e.clientX, e.clientY]);
      if (ptrs.size === 2) {
        const [a, b] = [...ptrs.values()], dist = Math.hypot(a[0] - b[0], a[1] - b[1]);
        if (pinch0) state.zoom = clampZoom(pinch0.zoom * dist / pinch0.dist); else pinch0 = { dist, zoom: state.zoom };
      } else {
        const px = svg.getBoundingClientRect().width / W;   // 화면 픽셀 → viewBox
        const k = 0.5 / state.zoom / (px || 1);
        state.lon -= (e.clientX - prev[0]) * k;
        state.lat = clampLat(state.lat + (e.clientY - prev[1]) * k);
      }
      redraw();
    });
    const up = e => { ptrs.delete(e.pointerId); if (ptrs.size < 2) pinch0 = null; if (!ptrs.size) svg.style.cursor = "grab"; };
    svg.addEventListener("pointerup", up); svg.addEventListener("pointercancel", up);
    svg.addEventListener("wheel", e => { e.preventDefault(); state.zoom = clampZoom(state.zoom * Math.exp(-e.deltaY * 0.0015)); redraw(); }, { passive: false });
    svg.addEventListener("dblclick", () => { api.center(); });

    const api = {
      update(geo) {
        const next = new Map();
        for (const p of (geo && geo.points) || []) {
          const ts = Date.parse(p.last_alert && p.last_alert.ts);
          if (!Number.isFinite(ts)) continue;
          next.set(p.ip, ts);
          if (alertTimes && ts > (alertTimes.get(p.ip) || 0)) flashes.set(p.ip, performance.now() + 1800);
        }
        for (const [ip, until] of flashes) if (!next.has(ip) || until <= performance.now()) flashes.delete(ip);
        alertTimes = next;
        state.geo = geo; redraw();
      },
      center() {
        const h = state.geo && state.geo.home;
        state.lon = h ? h.lon : 127; state.lat = h ? clampLat(h.lat - 7) : 30; state.zoom = 1; redraw();
      },
      zoomTo(lon, lat, zoom) { state.lon = lon; state.lat = clampLat(lat); state.zoom = clampZoom(zoom || 3); redraw(); },
      state,
    };
    draw();
    return api;
  }

  window.EGViz = { line, levelBars, donut, alertGroups, globe, human, LEVEL_COLOR };
})();
