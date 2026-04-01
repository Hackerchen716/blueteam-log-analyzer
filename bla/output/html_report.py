"""
HTML 报告输出
生成独立单文件 HTML 报告（内嵌 CSS/JS，无需网络）
"""
from __future__ import annotations
import json
import datetime
from typing import List
from ..models import ParseResult, AnalysisSummary, ThreatLevel


def _level_color_hex(level: ThreatLevel) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#22c55e",
        "info":     "#3b82f6",
    }.get(level.value, "#6b7280")


def _level_bg_hex(level: ThreatLevel) -> str:
    return {
        "critical": "#450a0a",
        "high":     "#431407",
        "medium":   "#422006",
        "low":      "#052e16",
        "info":     "#172554",
    }.get(level.value, "#1f2937")


def generate_html_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 准备数据
    total_events = sum(r.stats.total for r in parse_results)
    crit  = sum(r.stats.critical for r in parse_results)
    high  = sum(r.stats.high for r in parse_results)
    med   = sum(r.stats.medium for r in parse_results)
    low   = sum(r.stats.low for r in parse_results)
    info  = sum(r.stats.info for r in parse_results)

    # 所有 IP 汇总
    all_ips: dict = {}
    for r in parse_results:
        for ip_info in r.stats.top_ips:
            all_ips[ip_info["ip"]] = all_ips.get(ip_info["ip"], 0) + ip_info["count"]
    top_ips = sorted(all_ips.items(), key=lambda x: x[1], reverse=True)[:15]

    # 告警 HTML
    alerts_html = ""
    for i, alert in enumerate(summary.alerts, 1):
        color = _level_color_hex(alert.level)
        bg    = _level_bg_hex(alert.level)
        evidence_items = "".join(f"<li>{e}</li>" for e in alert.evidence)
        alerts_html += f"""
        <div class="alert-card" style="border-left:4px solid {color}; background:{bg};">
          <div class="alert-header">
            <span class="badge" style="background:{color};">{alert.level.label}</span>
            <span class="alert-num">#{i:02d}</span>
            <strong>{alert.rule_name}</strong>
            <span class="mitre-tag">{alert.mitre_attack}</span>
            <span class="phase-tag">{alert.mitre_phase}</span>
          </div>
          <p class="alert-desc">{alert.description}</p>
          <div class="alert-meta">
            <span>置信度: {alert.confidence}</span>
            <span>时间: {alert.timestamp}</span>
            <span>影响事件: {len(alert.affected_events)}</span>
          </div>
          <details>
            <summary>证据详情</summary>
            <ul class="evidence-list">{evidence_items}</ul>
          </details>
          <div class="recommendation">💡 {alert.recommendation}</div>
        </div>"""

    # 时间线 HTML
    timeline_html = ""
    for entry in summary.timeline[-100:]:
        color = _level_color_hex(entry.level)
        mitre = f'<span class="mitre-tag">{entry.mitre_attack}</span>' if entry.mitre_attack else ""
        timeline_html += f"""
        <div class="tl-entry">
          <div class="tl-dot" style="background:{color};"></div>
          <div class="tl-content">
            <span class="tl-time">{entry.timestamp}</span>
            <span class="badge" style="background:{color}; font-size:10px;">{entry.level.label}</span>
            {mitre}
            <span class="tl-cat">[{entry.category}]</span>
            <span class="tl-msg">{entry.message}</span>
          </div>
        </div>"""

    # 攻击链 HTML
    chain_html = ""
    chain_phases = ["侦察","初始访问","执行","持久化","权限提升","防御规避","凭据访问","横向移动","命令控制"]
    active_phases = {c.phase: c for c in summary.attack_chain}
    for phase in chain_phases:
        if phase in active_phases:
            c = active_phases[phase]
            color = _level_color_hex(c.level)
            techs = ", ".join(c.techniques[:3])
            chain_html += f"""
            <div class="chain-item active" style="border-color:{color};">
              <div class="chain-phase" style="color:{color};">{phase}</div>
              <div class="chain-count">{c.event_count} 事件</div>
              <div class="chain-techs">{techs}</div>
            </div>
            <div class="chain-arrow">→</div>"""
        else:
            chain_html += f"""
            <div class="chain-item inactive">
              <div class="chain-phase">{phase}</div>
            </div>
            <div class="chain-arrow">→</div>"""

    # IP 柱状图数据
    ip_labels = json.dumps([ip for ip, _ in top_ips], ensure_ascii=False)
    ip_counts = json.dumps([cnt for _, cnt in top_ips])

    # 文件列表 HTML
    files_html = ""
    for r in parse_results:
        files_html += f"""
        <tr>
          <td>{r.file_name}</td>
          <td>{r.log_type}</td>
          <td>{r.stats.total}</td>
          <td style="color:#ef4444;">{r.stats.critical}</td>
          <td style="color:#f97316;">{r.stats.high}</td>
          <td style="color:#eab308;">{r.stats.medium}</td>
          <td>{r.file_size_bytes//1024} KB</td>
          <td>{r.parse_time_ms:.0f}ms</td>
          <td>{r.stats.time_start[:10] if r.stats.time_start else '-'}</td>
        </tr>"""

    # 建议 HTML
    recs_html = "".join(f"<li>{r}</li>" for r in summary.recommendations)

    risk_color = _level_color_hex(summary.risk_level)
    risk_score = summary.risk_score

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLA 分析报告 - {now}</title>
<style>
  :root {{
    --bg: #0f172a; --bg2: #1e293b; --bg3: #334155;
    --text: #e2e8f0; --text2: #94a3b8; --border: #334155;
    --crit: #ef4444; --high: #f97316; --med: #eab308;
    --low: #22c55e; --info: #3b82f6; --accent: #06b6d4;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'SF Mono', 'JetBrains Mono', monospace; background: var(--bg); color: var(--text); font-size: 13px; line-height: 1.6; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  h1 {{ font-size: 22px; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 15px; color: var(--accent); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  h3 {{ font-size: 13px; color: var(--text2); margin-bottom: 8px; }}
  .header {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
  .header-left h1 span {{ color: var(--text2); font-size: 14px; }}
  .header-meta {{ color: var(--text2); font-size: 11px; }}
  .risk-badge {{ text-align: center; }}
  .risk-score {{ font-size: 48px; font-weight: bold; color: {risk_color}; line-height: 1; }}
  .risk-label {{ font-size: 12px; color: var(--text2); }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 32px; font-weight: bold; }}
  .stat-label {{ font-size: 11px; color: var(--text2); margin-top: 4px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }}
  .alert-card {{ border-radius: 8px; padding: 14px; margin-bottom: 12px; }}
  .alert-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }}
  .alert-num {{ color: var(--text2); font-size: 11px; }}
  .alert-desc {{ margin-bottom: 8px; }}
  .alert-meta {{ display: flex; gap: 16px; font-size: 11px; color: var(--text2); margin-bottom: 8px; }}
  .mitre-tag {{ background: #1e3a5f; color: #60a5fa; padding: 1px 6px; border-radius: 3px; font-size: 11px; }}
  .phase-tag {{ background: #1e2a1e; color: #86efac; padding: 1px 6px; border-radius: 3px; font-size: 11px; }}
  .evidence-list {{ margin: 8px 0 8px 16px; color: var(--text2); font-size: 12px; }}
  .recommendation {{ background: #1c2a1c; border-left: 3px solid #22c55e; padding: 8px 12px; border-radius: 4px; font-size: 12px; margin-top: 8px; }}
  details summary {{ cursor: pointer; color: var(--accent); font-size: 12px; margin: 4px 0; }}
  .tl-entry {{ display: flex; gap: 12px; margin-bottom: 8px; align-items: flex-start; }}
  .tl-dot {{ width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }}
  .tl-content {{ flex: 1; display: flex; flex-wrap: wrap; gap: 6px; align-items: baseline; }}
  .tl-time {{ color: var(--text2); font-size: 11px; white-space: nowrap; }}
  .tl-cat {{ color: var(--text2); font-size: 11px; }}
  .tl-msg {{ color: var(--text); }}
  .chain-wrapper {{ display: flex; align-items: center; flex-wrap: wrap; gap: 4px; overflow-x: auto; padding: 8px 0; }}
  .chain-item {{ border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; min-width: 90px; text-align: center; }}
  .chain-item.active {{ background: var(--bg3); }}
  .chain-item.inactive {{ opacity: 0.35; }}
  .chain-phase {{ font-size: 12px; font-weight: bold; }}
  .chain-count {{ font-size: 11px; color: var(--text2); }}
  .chain-techs {{ font-size: 10px; color: var(--text2); margin-top: 2px; }}
  .chain-arrow {{ color: var(--text2); font-size: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: var(--bg3); color: var(--text2); padding: 8px 10px; text-align: left; font-weight: normal; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--bg3); }}
  .rec-list {{ list-style: none; }}
  .rec-list li {{ padding: 8px 12px; border-left: 3px solid var(--accent); margin-bottom: 8px; background: var(--bg3); border-radius: 0 4px 4px 0; }}
  canvas {{ max-height: 250px; }}
  .tab-bar {{ display: flex; gap: 4px; margin-bottom: 12px; }}
  .tab {{ padding: 6px 14px; border-radius: 6px 6px 0 0; cursor: pointer; background: var(--bg3); color: var(--text2); border: 1px solid var(--border); border-bottom: none; font-size: 12px; }}
  .tab.active {{ background: var(--bg2); color: var(--text); }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 4px 12px; border-radius: 4px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); cursor: pointer; font-size: 12px; }}
  .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
  input[type=text] {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 4px 10px; border-radius: 4px; font-size: 12px; width: 240px; }}
</style>
</head>
<body>
<div class="container">

  <!-- 标题 -->
  <div class="header">
    <div class="header-left">
      <h1>🛡 BlueTeam Log Analyzer <span>| 蓝队应急响应日志分析报告</span></h1>
      <div class="header-meta">
        生成时间: {now} &nbsp;|&nbsp; 分析文件: {summary.files_analyzed} 个 &nbsp;|&nbsp;
        总事件: {total_events} 条 &nbsp;|&nbsp; 告警: {len(summary.alerts)} 个
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-score">{risk_score}</div>
      <div class="risk-label">风险评分 / 100</div>
      <div><span class="badge" style="background:{risk_color}; margin-top:4px;">{summary.risk_level.label}</span></div>
    </div>
  </div>

  <!-- 统计卡片 -->
  <div class="grid-4">
    <div class="stat-card"><div class="stat-num" style="color:#ef4444;">{crit}</div><div class="stat-label">严重事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#f97316;">{high}</div><div class="stat-label">高危事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#eab308;">{med}</div><div class="stat-label">中危事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#22c55e;">{low}</div><div class="stat-label">低危事件</div></div>
  </div>

  <!-- ATT&CK 攻击链 -->
  <h2>⛓ ATT&CK 攻击链</h2>
  <div class="card">
    <div class="chain-wrapper">{chain_html}</div>
  </div>

  <!-- 图表区 -->
  <div class="grid-2">
    <div class="card">
      <h3>事件级别分布</h3>
      <canvas id="levelChart"></canvas>
    </div>
    <div class="card">
      <h3>Top 攻击源 IP</h3>
      <canvas id="ipChart"></canvas>
    </div>
  </div>

  <!-- 告警 -->
  <h2>🚨 威胁告警 ({len(summary.alerts)})</h2>
  <div class="filter-bar">
    <input type="text" id="alertSearch" placeholder="搜索告警..." oninput="filterAlerts()">
    <button class="filter-btn active" onclick="setFilter('all', this)">全部</button>
    <button class="filter-btn" onclick="setFilter('critical', this)" style="color:#ef4444;">严重</button>
    <button class="filter-btn" onclick="setFilter('high', this)" style="color:#f97316;">高危</button>
    <button class="filter-btn" onclick="setFilter('medium', this)" style="color:#eab308;">中危</button>
  </div>
  <div id="alertsContainer">{alerts_html}</div>

  <!-- 时间线 -->
  <h2>📅 关键事件时间线</h2>
  <div class="card" style="max-height:500px; overflow-y:auto;">
    {timeline_html}
  </div>

  <!-- 文件详情 -->
  <h2>📁 文件解析详情</h2>
  <div class="card">
    <table>
      <thead><tr>
        <th>文件名</th><th>类型</th><th>总事件</th>
        <th>严重</th><th>高危</th><th>中危</th>
        <th>大小</th><th>耗时</th><th>起始日期</th>
      </tr></thead>
      <tbody>{files_html}</tbody>
    </table>
  </div>

  <!-- 建议 -->
  <h2>💡 应急处置建议</h2>
  <div class="card">
    <ul class="rec-list">{recs_html}</ul>
  </div>

</div>

<script>
// 图表
(function() {{
  const ctx1 = document.getElementById('levelChart').getContext('2d');
  new Chart(ctx1, {{
    type: 'doughnut',
    data: {{
      labels: ['严重','高危','中危','低危','信息'],
      datasets: [{{ data: [{crit},{high},{med},{low},{info}],
        backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6'],
        borderWidth: 0 }}]
    }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }}, cutout: '60%' }}
  }});

  const ctx2 = document.getElementById('ipChart').getContext('2d');
  new Chart(ctx2, {{
    type: 'bar',
    data: {{
      labels: {ip_labels},
      datasets: [{{ label: '请求次数', data: {ip_counts},
        backgroundColor: '#ef4444', borderRadius: 3 }}]
    }},
    options: {{
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#334155' }} }},
        y: {{ ticks: {{ color: '#94a3b8', font: {{ size: 10 }} }}, grid: {{ display: false }} }}
      }}
    }}
  }});
}})();

// 告警过滤
let currentFilter = 'all';
function setFilter(level, btn) {{
  currentFilter = level;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterAlerts();
}}
function filterAlerts() {{
  const q = document.getElementById('alertSearch').value.toLowerCase();
  document.querySelectorAll('.alert-card').forEach(card => {{
    const text = card.textContent.toLowerCase();
    const levelMatch = currentFilter === 'all' || card.querySelector('.badge')?.textContent.includes(
      {{critical:'严重',high:'高危',medium:'中危',low:'低危'}}[currentFilter] || currentFilter
    );
    card.style.display = (text.includes(q) && levelMatch) ? '' : 'none';
  }});
}}
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  [✓] HTML 报告已保存: {output_path}")
    print(f"      用浏览器打开: open {output_path}")
