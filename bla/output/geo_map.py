"""Offline GeoIP map rendering for HTML reports."""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter, defaultdict
from html import escape
from importlib import resources
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import ParseResult
from ..utils.helpers import safe_print, sanitize_report_text


MAX_GEO_IPS = 80
MAX_DETAIL_ROWS = 18

COUNTRY_ALIASES = {
    "united states": "United States of America",
    "usa": "United States of America",
    "u.s.": "United States of America",
    "u.s.a.": "United States of America",
    "russian federation": "Russia",
    "korea, republic of": "South Korea",
    "republic of korea": "South Korea",
    "viet nam": "Vietnam",
    "iran, islamic republic of": "Iran",
    "czechia": "Czech Republic",
    "united kingdom of great britain and northern ireland": "United Kingdom",
}

DISPLAY_ALIASES = {
    "United States of America": "United States",
}

COUNTRY_KEYS = (
    "geo_country",
    "country",
    "country_name",
    "src_country",
    "source_country",
    "source_country_name",
    "geoip_country",
)
REGION_KEYS = ("geo_region", "region", "regionName", "src_region", "source_region", "geoip_region")
CITY_KEYS = ("geo_city", "city", "src_city", "source_city", "geoip_city")
LAT_KEYS = ("lat", "latitude", "geo_lat", "geoip_lat", "src_lat", "source_lat")
LON_KEYS = ("lon", "lng", "longitude", "geo_lon", "geo_lng", "geoip_lon", "src_lon", "source_lon")


def build_geo_map_section(
    parse_results: Sequence[ParseResult],
    geoip_cache_path: Optional[str] = None,
) -> Tuple[str, str]:
    """Return ``(css, html)`` for the optional geolocation section.

    The function is intentionally offline-only. It reads GeoIP data from event
    fields or from an explicit local JSON cache, and returns empty strings when
    no public source IP can be geolocated.
    """
    ip_counts, ip_sources, event_geo = _collect_public_source_ips(parse_results)
    if not ip_counts:
        return "", ""

    cache_path = geoip_cache_path or os.environ.get("BLA_GEOIP_CACHE")
    cache_geo = _load_geoip_cache(cache_path)
    located = []
    for ip, count in ip_counts.most_common(MAX_GEO_IPS):
        geo = event_geo.get(ip) or cache_geo.get(ip)
        if not geo or not geo.get("country"):
            continue
        country = _canonical_country(str(geo["country"]))
        located.append({
            "ip": ip,
            "count": count,
            "country": country,
            "display_country": _display_country(country),
            "region": str(geo.get("region") or ""),
            "city": str(geo.get("city") or ""),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "sources": ip_sources.get(ip, Counter()),
            "source": geo.get("source") or "cache",
        })

    if not located:
        return "", ""

    country_hits: Counter = Counter()
    country_ips: Dict[str, set] = defaultdict(set)
    for item in located:
        key = _country_key(item["country"])
        country_hits[key] += item["count"]
        country_ips[key].add(item["ip"])

    country_display = {
        _country_key(item["country"]): item["display_country"]
        for item in located
    }
    map_svg = _render_world_svg(country_hits, country_display)
    if not map_svg:
        return "", ""

    top_country_rows = _render_country_rows(country_hits, country_ips, country_display)
    ip_rows = _render_ip_rows(located)
    located_ip_count = len({item["ip"] for item in located})
    located_event_count = sum(item["count"] for item in located)

    css = _geo_css()
    html = f"""
  <h2>攻击源地理分布</h2>
  <div class="geo-layout">
    <section class="geo-card geo-map-panel">
      <div class="geo-head">
        <div>
          <h3>可定位公网源 IP</h3>
          <p>仅使用日志自带地理字段或本地 GeoIP 缓存；内网、回环、保留地址和无法匹配位置的 IP 不进入地图。</p>
        </div>
        <span class="geo-pill">离线热力图</span>
      </div>
      <div class="geo-map-wrap">{map_svg}</div>
      <div class="geo-foot">
        <span>已定位 {located_ip_count} 个公网源 IP</span>
        <span>覆盖 {located_event_count} 条事件命中</span>
      </div>
    </section>
    <aside class="geo-side">
      <section class="geo-card">
        <h3>Top 国家/地区</h3>
        <div class="geo-country-list">{top_country_rows}</div>
      </section>
    </aside>
  </div>
  <section class="geo-card geo-ip-panel">
    <h3>源 IP 明细</h3>
    <div class="geo-ip-list">{ip_rows}</div>
  </section>"""
    return css, html


def _collect_public_source_ips(parse_results: Sequence[ParseResult]) -> Tuple[Counter, Dict[str, Counter], Dict[str, dict]]:
    counts: Counter = Counter()
    sources: Dict[str, Counter] = defaultdict(Counter)
    geo_by_ip: Dict[str, dict] = {}

    for result in parse_results:
        source_label = result.log_type or "log"
        for event in result.events:
            ip = _event_source_ip(event)
            if not _is_public_ip(ip):
                continue
            counts[ip] += 1
            sources[ip][_event_source_label(event, source_label)] += 1
            event_geo = _extract_event_geo(event.details)
            if event_geo and ip not in geo_by_ip:
                event_geo["source"] = "event"
                geo_by_ip[ip] = event_geo
    return counts, sources, geo_by_ip


def _event_source_ip(event: Any) -> str:
    details = getattr(event, "details", {}) or {}
    for key in ("src_ip", "source_ip", "client_ip", "remote_ip", "ip"):
        value = details.get(key)
        if value:
            return str(value).strip()
    return str(getattr(event, "ip", "") or "").strip()


def _event_source_label(event: Any, fallback: str) -> str:
    details = getattr(event, "details", {}) or {}
    return str(details.get("source_type") or getattr(event, "source", "") or fallback or "log")


def _is_public_ip(value: str) -> bool:
    try:
        return ip_address(str(value).strip()).is_global
    except ValueError:
        return False


def _load_geoip_cache(path: Optional[str]) -> Dict[str, dict]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        safe_print(
            "  [!] GeoIP 缓存不可用，地图将跳过该缓存:",
            sanitize_report_text(path),
            f"({exc.__class__.__name__})",
        )
        return {}
    records: Iterable[Any]
    if isinstance(data, dict):
        records = (
            dict(value, query=key) if isinstance(value, dict) else {"query": key, "country": value}
            for key, value in data.items()
        )
    elif isinstance(data, list):
        records = data
    else:
        return {}

    cache: Dict[str, dict] = {}
    for raw in records:
        if not isinstance(raw, dict):
            continue
        if raw.get("status") and str(raw.get("status")).lower() not in {"success", "ok"}:
            continue
        ip = str(raw.get("query") or raw.get("ip") or raw.get("src_ip") or "").strip()
        if not _is_public_ip(ip):
            continue
        geo = _extract_event_geo(raw)
        if geo and geo.get("country"):
            geo["source"] = "cache"
            cache[ip] = geo
    return cache


def _extract_event_geo(details: Dict[str, Any]) -> Optional[dict]:
    country = _first(details, COUNTRY_KEYS)
    if not country:
        return None
    geo = {
        "country": _canonical_country(country),
        "region": _first(details, REGION_KEYS) or "",
        "city": _first(details, CITY_KEYS) or "",
        "lat": _float_or_none(_first(details, LAT_KEYS)),
        "lon": _float_or_none(_first(details, LON_KEYS)),
    }
    return geo


def _first(details: Dict[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        value = details.get(key)
        if value not in (None, "", "-", "null", "None"):
            return str(value).strip()
    return ""


def _float_or_none(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _canonical_country(value: str) -> str:
    country = str(value or "").strip()
    return COUNTRY_ALIASES.get(country.lower(), country)


def _display_country(value: str) -> str:
    return DISPLAY_ALIASES.get(value, value)


def _country_key(value: str) -> str:
    canonical = _canonical_country(value)
    return re.sub(r"[^a-z0-9]+", "", canonical.lower())


def _render_world_svg(country_hits: Counter, country_display: Dict[str, str]) -> str:
    try:
        text = resources.files("bla.output").joinpath("assets", "world-countries.geojson").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return ""
    try:
        geojson = json.loads(text)
    except json.JSONDecodeError:
        return ""

    max_hits = max(country_hits.values(), default=1)
    paths = []
    for feature in geojson.get("features", []):
        props = feature.get("properties", {}) or {}
        geometry = feature.get("geometry", {}) or {}
        path = _geometry_path(geometry)
        if not path:
            continue
        key = _feature_country_key(props)
        hits = country_hits.get(key, 0)
        if hits:
            opacity = 0.34 + 0.58 * math.sqrt(hits / max_hits)
            fill = "#e26f20"
            stroke = "#ffffff"
            stroke_width = "0.8"
            label = country_display.get(key) or _display_country(props.get("ADMIN") or props.get("NAME") or "")
            title = f"<title>{_h(label)}: {hits} 次</title>"
            cls = "geo-country is-hit"
        else:
            opacity = 1.0
            fill = "#dbe8f4"
            stroke = "#c5d4e4"
            stroke_width = "0.45"
            title = ""
            cls = "geo-country"
        paths.append(
            f'<path class="{cls}" d="{path}" fill="{fill}" fill-opacity="{opacity:.2f}" '
            f'stroke="{stroke}" stroke-width="{stroke_width}">{title}</path>'
        )

    grid = []
    for lon in range(-120, 181, 60):
        x = _project(lon, 0)[0]
        grid.append(f'<line x1="{x:.1f}" y1="18" x2="{x:.1f}" y2="500" />')
    for lat in range(-60, 81, 30):
        y = _project(0, lat)[1]
        grid.append(f'<line x1="20" y1="{y:.1f}" x2="980" y2="{y:.1f}" />')

    return (
        '<svg class="geo-map" viewBox="0 0 1000 520" role="img" '
        'aria-label="攻击源国家地区热力图" xmlns="http://www.w3.org/2000/svg">'
        '<rect x="0" y="0" width="1000" height="520" rx="18" fill="#f8fbff"/>'
        f'<g class="geo-grid">{"".join(grid)}</g>'
        f'<g class="geo-countries">{"".join(paths)}</g>'
        '<g class="geo-legend">'
        '<circle cx="38" cy="485" r="6" fill="#e26f20"/>'
        '<text x="52" y="490">命中越多颜色越深</text>'
        '</g>'
        '</svg>'
    )


def _feature_country_key(props: Dict[str, Any]) -> str:
    for name_key in ("ADMIN", "NAME_LONG", "NAME_EN", "NAME", "SOVEREIGNT"):
        value = props.get(name_key)
        if value:
            key = _country_key(str(value))
            if key:
                return key
    return ""


def _geometry_path(geometry: Dict[str, Any]) -> str:
    gtype = geometry.get("type")
    coords = geometry.get("coordinates") or []
    pieces: List[str] = []
    if gtype == "Polygon":
        pieces.extend(_polygon_path(coords))
    elif gtype == "MultiPolygon":
        for polygon in coords:
            pieces.extend(_polygon_path(polygon))
    return " ".join(pieces)


def _polygon_path(rings: Sequence[Sequence[Sequence[float]]]) -> List[str]:
    pieces = []
    for ring in rings:
        if not ring:
            continue
        commands = []
        for idx, point in enumerate(ring):
            if len(point) < 2:
                continue
            x, y = _project(float(point[0]), float(point[1]))
            commands.append(("M" if idx == 0 else "L") + f"{x:.1f},{y:.1f}")
        if commands:
            commands.append("Z")
            pieces.append(" ".join(commands))
    return pieces


def _project(lon: float, lat: float) -> Tuple[float, float]:
    x = (lon + 180.0) / 360.0 * 1000.0
    y = (90.0 - lat) / 180.0 * 520.0
    return x, y


def _render_country_rows(country_hits: Counter, country_ips: Dict[str, set], country_display: Dict[str, str]) -> str:
    max_hits = max(country_hits.values(), default=1)
    rows = []
    for idx, (country_key, hits) in enumerate(country_hits.most_common(10), 1):
        width = max(6, hits / max_hits * 100)
        label = country_display.get(country_key, country_key)
        ip_count = len(country_ips.get(country_key, set()))
        rows.append(f"""
          <div class="geo-country-row">
            <span class="geo-rank">{idx:02d}</span>
            <div class="geo-country-main">
              <strong>{_h(label)}</strong>
              <em style="width:{width:.1f}%"></em>
            </div>
            <span class="geo-count">{hits} 次 / {ip_count} IP</span>
          </div>""")
    return "".join(rows)


def _render_ip_rows(located: List[dict]) -> str:
    rows = []
    for item in sorted(located, key=lambda value: value["count"], reverse=True)[:MAX_DETAIL_ROWS]:
        place = " / ".join(part for part in (item["display_country"], item["region"], item["city"]) if part)
        sources = ", ".join(label for label, _count in item["sources"].most_common(3)) or "-"
        rows.append(f"""
          <div class="geo-ip-row">
            <code>{_h(item['ip'])}</code>
            <span>{_h(place)}</span>
            <small>{_h(sources)}</small>
            <b>{item['count']}</b>
          </div>""")
    return "".join(rows)


def _geo_css() -> str:
    return """
  .geo-layout { display:grid; grid-template-columns:minmax(0, 2fr) minmax(340px, .68fr); gap:18px; margin-bottom:18px; align-items:start; }
  .geo-card { background:var(--surface); border:1px solid var(--border); border-radius:14px; box-shadow:var(--shadow); padding:18px; }
  .geo-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:14px; }
  .geo-head h3, .geo-side h3, .geo-ip-panel h3 { color:var(--text); font-size:16px; margin-bottom:4px; }
  .geo-head p { color:var(--muted); font-size:12px; max-width:720px; }
  .geo-pill { flex-shrink:0; color:#0e7490; background:#effafa; border:1px solid #bfe8ef; border-radius:999px; padding:6px 11px; font-size:12px; font-weight:800; }
  .geo-map-wrap { border:1px solid #dbe6f1; border-radius:14px; background:#f8fbff; overflow:hidden; }
  .geo-map { display:block; width:100%; height:auto; min-height:360px; }
  .geo-grid line { stroke:#e7eff8; stroke-width:.7; }
  .geo-country { vector-effect:non-scaling-stroke; transition:fill-opacity .12s ease, stroke-width .12s ease; }
  .geo-country.is-hit:hover { stroke:#123243; stroke-width:1.1; fill-opacity:1; }
  .geo-legend text { fill:#667085; font-size:13px; font-weight:700; }
  .geo-foot { display:flex; flex-wrap:wrap; gap:10px; color:var(--muted); font-size:12px; margin-top:10px; }
  .geo-foot span { background:#f8fafc; border:1px solid #e2e8f0; border-radius:999px; padding:4px 9px; }
  .geo-side { display:grid; gap:18px; align-content:start; }
  .geo-country-row { display:grid; grid-template-columns:42px minmax(0, 1fr) auto; gap:10px; align-items:center; padding:10px 0; border-bottom:1px solid #edf1f6; }
  .geo-country-row:last-child { border-bottom:0; }
  .geo-rank { color:var(--faint); font-weight:850; }
  .geo-country-main strong { display:block; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .geo-country-main em { display:block; height:5px; margin-top:6px; border-radius:999px; background:linear-gradient(90deg, #f5a25d, #d92d20); }
  .geo-count { color:var(--muted); font-size:11px; white-space:nowrap; }
  .geo-ip-panel { margin-bottom:24px; }
  .geo-ip-list { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); column-gap:22px; }
  .geo-ip-row { display:grid; grid-template-columns:136px minmax(0, 1fr) 96px 48px; gap:12px; align-items:center; padding:10px 0; border-bottom:1px solid #edf1f6; }
  .geo-ip-row:last-child { border-bottom:0; }
  .geo-ip-row code { color:#0e7490; background:#f8fafc; border:1px solid #dbe6f1; border-radius:5px; padding:4px 7px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .geo-ip-row span { color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .geo-ip-row b { text-align:right; }
  .geo-ip-row small { color:var(--faint); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  @media (max-width: 1180px) { .geo-ip-list { grid-template-columns:1fr; } }
  @media (max-width: 1060px) { .geo-layout { grid-template-columns:1fr; } .geo-map { min-height:260px; } }
  @media (max-width: 720px) { .geo-head { display:block; } .geo-pill { display:inline-block; margin-top:8px; } .geo-country-row { grid-template-columns:34px 1fr; } .geo-count { grid-column:2; } .geo-ip-row { grid-template-columns:1fr 44px; } .geo-ip-row code, .geo-ip-row span, .geo-ip-row small { grid-column:1 / 3; } .geo-ip-row b { grid-column:2; grid-row:1; } }
"""


def _h(value: Any) -> str:
    return escape(sanitize_report_text(value), quote=True)
