#!/usr/bin/env python3
"""
AI-IDS SIEM Dashboard - Real-time attack monitoring with live charts
Only displays attacks, filters out benign traffic
"""
import json, os, time
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, deque

from flask import Flask, jsonify, render_template_string, request, send_from_directory

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch

app = Flask(__name__)

BASE_DIR    = Path('/home/aashish/AI-IDS-Project')
SHARED_FILE = BASE_DIR / 'data' / 'live_results.json'
REPORTS_DIR = BASE_DIR / 'reports'
REPORTS_DIR.mkdir(exist_ok=True)

def read_shared():
    """Read latest data from the shared JSON file"""
    try:
        with open(SHARED_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"traffic": [], "alerts": []}

# ─── PDF REPORT (same as before) ─────────────────────────
def generate_pdf_report():
    data = read_shared()
    alerts = data.get("alerts", [])
    total = len(alerts)

    filename = f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = REPORTS_DIR / filename

    # Pie chart
    chart_path = REPORTS_DIR / '_chart.png'
    if alerts:
        counts = Counter(e['label'] for e in alerts)
        fig, ax = plt.subplots(figsize=(5, 3))
        colors = {'DDoS': '#ef4444', 'PortScan': '#f59e0b', 'Bot': '#8b5cf6'}
        ax.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%', startangle=90,
               colors=[colors.get(k, '#64748b') for k in counts.keys()])
        ax.set_title("Attack Distribution")
        fig.savefig(chart_path, dpi=100, bbox_inches='tight')
        plt.close(fig)
    else:
        # Empty chart
        fig, ax = plt.subplots(figsize=(5, 3))
        ax.text(0.5, 0.5, 'No Attacks Detected', ha='center', va='center', fontsize=14)
        ax.axis('off')
        fig.savefig(chart_path, dpi=100, bbox_inches='tight')
        plt.close(fig)

    doc = SimpleDocTemplate(str(filepath), pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    title_style   = ParagraphStyle('T', parent=styles['Title'], textColor=HexColor('#1a5276'), fontSize=22)
    heading_style = ParagraphStyle('H', parent=styles['Heading2'], textColor=HexColor('#2e86c1'))
    story = []

    story.append(Paragraph("AI-Powered Intrusion Detection System", title_style))
    story.append(Paragraph(f"Report: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Attack Summary", heading_style))
    summary = [
        ["Metric", "Value"],
        ["Total Attacks Detected", str(total)],
        ["Model Accuracy", "99.81%"],
        ["Dataset", "CIC-IDS2017"],
    ]
    t = Table(summary, colWidths=[3*inch, 3*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), HexColor('#2e86c1')),
        ('TEXTCOLOR',(0,0),(-1,0), HexColor('#ffffff')),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,-1),11),
        ('BACKGROUND',(0,1),(-1,-1), HexColor('#eaf2f8')),
        ('GRID',(0,0),(-1,-1),0.5, HexColor('#aed6f1')),
        ('TOPPADDING',(0,0),(-1,-1),6),
        ('BOTTOMPADDING',(0,0),(-1,-1),6),
    ]))
    story.append(t)
    story.append(Spacer(1, 18))

    story.append(Paragraph("Attack Distribution", heading_style))
    story.append(Image(str(chart_path), width=4*inch, height=2.4*inch))
    story.append(Spacer(1, 18))

    story.append(Paragraph("Recent Attacks", heading_style))
    alert_rows = [["Time", "Attack Type", "Confidence", "Dst Port"]]
    for a in alerts[-20:]:
        alert_rows.append([
            datetime.fromisoformat(a['timestamp']).strftime('%H:%M:%S'),
            a['label'],
            f"{a['confidence']}%",
            str(a.get('dst_port', '—'))
        ])
    if len(alert_rows) == 1:
        alert_rows.append(["—", "No attacks detected", "—", "—"])

    t2 = Table(alert_rows, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1*inch])
    t2.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), HexColor('#e74c3c')),
        ('TEXTCOLOR',(0,0),(-1,0), HexColor('#ffffff')),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,-1),10),
        ('BACKGROUND',(0,1),(-1,-1), HexColor('#fadbd8')),
        ('GRID',(0,0),(-1,-1),0.5, HexColor('#e74c3c')),
        ('TOPPADDING',(0,0),(-1,-1),5),
        ('BOTTOMPADDING',(0,0),(-1,-1),5),
    ]))
    story.append(t2)

    doc.build(story)
    chart_path.unlink(missing_ok=True)
    return filename

# ─── DASHBOARD HTML ──────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-IDS SIEM Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Inter','Segoe UI',sans-serif; background:#0a0e1a; color:#e2e8f0; min-height:100vh; }
  
  header {
    background:linear-gradient(135deg,#1e293b,#0f172a);
    border-bottom:2px solid #334155;
    padding:16px 32px;
    display:flex;
    align-items:center;
    justify-content:space-between;
  }
  header h1 { font-size:1.5rem; color:#38bdf8; font-weight:700; }
  .status { display:flex; align-items:center; gap:12px; }
  .status-dot {
    width:12px; height:12px;
    background:#22c55e;
    border-radius:50%;
    box-shadow:0 0 10px #22c55e;
    animation:pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .status-text { font-size:0.85rem; color:#94a3b8; font-weight:500; }

  .container { max-width:1600px; margin:24px auto; padding:0 24px; }

  /* Top Stats Cards */
  .stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:20px; margin-bottom:24px; }
  .stat-card {
    background:linear-gradient(145deg, #1e293b, #0f172a);
    border:1px solid #334155;
    border-radius:16px;
    padding:24px;
    position:relative;
    overflow:hidden;
  }
  .stat-card::before {
    content:'';
    position:absolute;
    top:0; left:0;
    width:100%; height:4px;
  }
  .stat-card.red::before { background:#ef4444; }
  .stat-card.amber::before { background:#f59e0b; }
  .stat-card.blue::before { background:#38bdf8; }
  .stat-card.purple::before { background:#a855f7; }
  
  .stat-label { font-size:0.75rem; text-transform:uppercase; letter-spacing:1.5px; color:#64748b; margin-bottom:8px; font-weight:600; }
  .stat-value { font-size:2.2rem; font-weight:800; margin-bottom:4px; }
  .stat-card.red .stat-value { color:#ef4444; }
  .stat-card.amber .stat-value { color:#f59e0b; }
  .stat-card.blue .stat-value { color:#38bdf8; }
  .stat-card.purple .stat-value { color:#a855f7; }
  .stat-change { font-size:0.7rem; color:#64748b; }

  /* Main Grid Layout */
  .main-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }
  .main-grid-full { display:grid; grid-template-columns:1fr; gap:20px; margin-bottom:20px; }
  
  .panel {
    background:linear-gradient(145deg, #1e293b, #0f172a);
    border:1px solid #334155;
    border-radius:16px;
    overflow:hidden;
    box-shadow:0 4px 6px rgba(0,0,0,0.3);
  }
  .panel-header {
    padding:16px 24px;
    border-bottom:1px solid #334155;
    display:flex;
    justify-content:space-between;
    align-items:center;
    background:rgba(15,23,42,0.6);
  }
  .panel-title { font-size:0.9rem; font-weight:700; color:#cbd5e1; text-transform:uppercase; letter-spacing:1px; }
  .panel-body { padding:24px; }

  /* Charts */
  .chart-container { position:relative; height:300px; }

  /* Attack Feed */
  .attack-feed { max-height:400px; overflow-y:auto; }
  .attack-feed::-webkit-scrollbar { width:6px; }
  .attack-feed::-webkit-scrollbar-track { background:#0f172a; }
  .attack-feed::-webkit-scrollbar-thumb { background:#334155; border-radius:3px; }
  
  .attack-item {
    padding:16px;
    border-left:4px solid;
    margin-bottom:12px;
    border-radius:8px;
    background:rgba(30,41,59,0.5);
    transition:all 0.2s;
  }
  .attack-item:hover { background:rgba(30,41,59,0.8); transform:translateX(4px); }
  .attack-item.ddos { border-color:#ef4444; }
  .attack-item.portscan { border-color:#f59e0b; }
  .attack-item.bot { border-color:#a855f7; }
  
  .attack-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
  .attack-type { font-weight:700; font-size:0.95rem; }
  .attack-item.ddos .attack-type { color:#ef4444; }
  .attack-item.portscan .attack-type { color:#f59e0b; }
  .attack-item.bot .attack-type { color:#a855f7; }
  
  .attack-time { font-size:0.75rem; color:#64748b; }
  .attack-details { font-size:0.8rem; color:#94a3b8; display:flex; gap:16px; }
  .attack-detail { display:flex; align-items:center; gap:6px; }
  
  .no-attacks {
    text-align:center;
    padding:60px 20px;
    color:#64748b;
    font-size:0.9rem;
  }
  .no-attacks-icon { font-size:3rem; margin-bottom:12px; opacity:0.3; }

  /* Buttons */
  .btn {
    padding:10px 20px;
    border:none;
    border-radius:8px;
    cursor:pointer;
    font-size:0.85rem;
    font-weight:600;
    text-transform:uppercase;
    letter-spacing:0.5px;
    transition:all 0.2s;
  }
  .btn-primary { background:#2563eb; color:#fff; }
  .btn-primary:hover { background:#1d4ed8; transform:translateY(-2px); box-shadow:0 4px 12px rgba(37,99,235,0.4); }

  /* Top Attacked Ports */
  .port-list { list-style:none; }
  .port-item {
    display:flex;
    justify-content:space-between;
    padding:12px 0;
    border-bottom:1px solid #1e293b;
  }
  .port-item:last-child { border-bottom:none; }
  .port-name { font-weight:600; color:#cbd5e1; }
  .port-count { color:#64748b; font-size:0.85rem; }

  /* Attack Timeline Table */
  .timeline-table { width:100%; border-collapse:collapse; font-size:0.85rem; }
  .timeline-table th {
    text-align:left;
    padding:12px;
    background:rgba(15,23,42,0.6);
    color:#64748b;
    font-weight:600;
    text-transform:uppercase;
    font-size:0.75rem;
    letter-spacing:1px;
  }
  .timeline-table td {
    padding:12px;
    border-bottom:1px solid #1e293b;
  }
  .timeline-table tr:hover { background:rgba(30,41,59,0.3); }
  
  .badge {
    display:inline-block;
    padding:4px 10px;
    border-radius:6px;
    font-size:0.75rem;
    font-weight:600;
    text-transform:uppercase;
  }
  .badge-ddos { background:rgba(239,68,68,0.2); color:#ef4444; }
  .badge-portscan { background:rgba(245,158,11,0.2); color:#f59e0b; }
  .badge-bot { background:rgba(168,85,247,0.2); color:#a855f7; }
</style>
</head>
<body>
<header>
  <h1>🛡️ AI-IDS SIEM Dashboard</h1>
  <div class="status">
    <span class="status-dot"></span>
    <span class="status-text">LIVE MONITORING</span>
  </div>
</header>

<div class="container">
  <!-- Top Stats -->
  <div class="stats-grid">
    <div class="stat-card red">
      <div class="stat-label">Total Attacks</div>
      <div class="stat-value" id="statTotal">0</div>
      <div class="stat-change">Since monitoring started</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-label">Attacks/Min</div>
      <div class="stat-value" id="statRate">0</div>
      <div class="stat-change">Average rate</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">DDoS Attacks</div>
      <div class="stat-value" id="statDDoS">0</div>
      <div class="stat-change">Distributed denial of service</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">Port Scans</div>
      <div class="stat-value" id="statPortScan">0</div>
      <div class="stat-change">Reconnaissance attempts</div>
    </div>
  </div>

  <!-- Charts Row -->
  <div class="main-grid">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Attack Timeline (Last Hour)</span>
      </div>
      <div class="panel-body">
        <div class="chart-container">
          <canvas id="timelineChart"></canvas>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Attack Distribution</span>
      </div>
      <div class="panel-body">
        <div class="chart-container">
          <canvas id="pieChart"></canvas>
        </div>
      </div>
    </div>
  </div>

  <!-- Live Feed and Top Ports -->
  <div class="main-grid">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">🚨 Live Attack Feed</span>
        <button class="btn btn-primary" onclick="generateReport()">📄 Export PDF</button>
      </div>
      <div class="panel-body">
        <div class="attack-feed" id="attackFeed">
          <div class="no-attacks">
            <div class="no-attacks-icon">🛡️</div>
            <div>Waiting for attacks...</div>
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Top Attacked Ports</span>
      </div>
      <div class="panel-body">
        <ul class="port-list" id="portList">
          <li class="port-item"><span class="port-name">No data yet</span><span class="port-count">—</span></li>
        </ul>
      </div>
    </div>
  </div>

  <!-- Attack Timeline Table -->
  <div class="main-grid-full">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Recent Attack Timeline</span>
      </div>
      <div class="panel-body">
        <table class="timeline-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Attack Type</th>
              <th>Confidence</th>
              <th>Destination Port</th>
              <th>Packets</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody id="timelineTable">
            <tr><td colspan="6" style="text-align:center;color:#64748b;padding:40px;">No attacks detected</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
// ─── CHARTS SETUP ────────────────────────────────────────
const timelineCtx = document.getElementById('timelineChart').getContext('2d');
const pieCtx = document.getElementById('pieChart').getContext('2d');

const timelineChart = new Chart(timelineCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Attacks per Minute',
      data: [],
      borderColor: '#ef4444',
      backgroundColor: 'rgba(239,68,68,0.1)',
      tension: 0.4,
      fill: true
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { mode: 'index', intersect: false }
    },
    scales: {
      y: { 
        beginAtZero: true,
        ticks: { color: '#64748b' },
        grid: { color: '#1e293b' }
      },
      x: {
        ticks: { color: '#64748b' },
        grid: { color: '#1e293b' }
      }
    }
  }
});

const pieChart = new Chart(pieCtx, {
  type: 'doughnut',
  data: {
    labels: ['DDoS', 'PortScan', 'Bot'],
    datasets: [{
      data: [0, 0, 0],
      backgroundColor: ['#ef4444', '#f59e0b', '#a855f7']
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { 
        position: 'bottom',
        labels: { color: '#cbd5e1', padding: 20 }
      }
    }
  }
});

// ─── DATA POLLING ────────────────────────────────────────
async function updateDashboard() {
  try {
    const res = await fetch('/api/alerts');
    const alerts = await res.json();
    
    if (!alerts.length) return;

    // Stats
    const total = alerts.length;
    const ddos = alerts.filter(a => a.label === 'DDoS').length;
    const portscan = alerts.filter(a => a.label === 'PortScan').length;
    const bot = alerts.filter(a => a.label === 'Bot').length;
    
    // Calculate rate (attacks per minute)
    if (alerts.length > 1) {
      const first = new Date(alerts[0].timestamp);
      const last = new Date(alerts[alerts.length-1].timestamp);
      const minutes = (last - first) / 60000;
      const rate = minutes > 0 ? (total / minutes).toFixed(1) : 0;
      document.getElementById('statRate').textContent = rate;
    }

    document.getElementById('statTotal').textContent = total;
    document.getElementById('statDDoS').textContent = ddos;
    document.getElementById('statPortScan').textContent = portscan;

    // Update timeline chart (last hour, grouped by minute)
    updateTimelineChart(alerts);

    // Update pie chart
    pieChart.data.datasets[0].data = [ddos, portscan, bot];
    pieChart.update();

    // Update attack feed (last 10)
    updateAttackFeed(alerts.slice(-10).reverse());

    // Update timeline table (last 15)
    updateTimelineTable(alerts.slice(-15).reverse());

    // Update top ports
    updateTopPorts(alerts);

  } catch(e) { console.error(e); }
}

function updateTimelineChart(alerts) {
  // Group by minute for last hour
  const now = new Date();
  const oneHourAgo = new Date(now - 60*60*1000);
  const minuteBuckets = {};
  
  for (let i = 0; i < 60; i++) {
    const time = new Date(oneHourAgo.getTime() + i * 60000);
    const label = time.toLocaleTimeString('en-US', {hour:'2-digit', minute:'2-digit'});
    minuteBuckets[label] = 0;
  }

  alerts.forEach(a => {
    const time = new Date(a.timestamp);
    if (time >= oneHourAgo) {
      const label = time.toLocaleTimeString('en-US', {hour:'2-digit', minute:'2-digit'});
      if (minuteBuckets[label] !== undefined) minuteBuckets[label]++;
    }
  });

  timelineChart.data.labels = Object.keys(minuteBuckets);
  timelineChart.data.datasets[0].data = Object.values(minuteBuckets);
  timelineChart.update();
}

function updateAttackFeed(alerts) {
  const feed = document.getElementById('attackFeed');
  if (!alerts.length) {
    feed.innerHTML = '<div class="no-attacks"><div class="no-attacks-icon">🛡️</div><div>Waiting for attacks...</div></div>';
    return;
  }

  feed.innerHTML = alerts.map(a => {
    const type = a.label.toLowerCase().replace(' ','');
    const time = new Date(a.timestamp).toLocaleTimeString();
    return `<div class="attack-item ${type}">
      <div class="attack-header">
        <span class="attack-type">⚠ ${a.label}</span>
        <span class="attack-time">${time}</span>
      </div>
      <div class="attack-details">
        <span class="attack-detail">🎯 Confidence: ${a.confidence}%</span>
        <span class="attack-detail">🔌 Port: ${a.dst_port}</span>
        <span class="attack-detail">📦 Packets: ${a.fwd_pkts + a.bwd_pkts}</span>
      </div>
    </div>`;
  }).join('');
}

function updateTimelineTable(alerts) {
  const tbody = document.getElementById('timelineTable');
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:40px;">No attacks detected</td></tr>';
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const badgeClass = a.label.toLowerCase().replace(' ','');
    return `<tr>
      <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
      <td><span class="badge badge-${badgeClass}">${a.label}</span></td>
      <td>${a.confidence}%</td>
      <td>${a.dst_port}</td>
      <td>${a.fwd_pkts + a.bwd_pkts}</td>
      <td>${a.duration}s</td>
    </tr>`;
  }).join('');
}

function updateTopPorts(alerts) {
  const ports = {};
  alerts.forEach(a => {
    const port = a.dst_port || 'Unknown';
    ports[port] = (ports[port] || 0) + 1;
  });

  const sorted = Object.entries(ports).sort((a,b) => b[1] - a[1]).slice(0,5);
  const list = document.getElementById('portList');
  
  if (!sorted.length) {
    list.innerHTML = '<li class="port-item"><span class="port-name">No data yet</span><span class="port-count">—</span></li>';
    return;
  }

  list.innerHTML = sorted.map(([port, count]) => 
    `<li class="port-item"><span class="port-name">Port ${port}</span><span class="port-count">${count} attacks</span></li>`
  ).join('');
}

async function generateReport() {
  const res = await fetch('/api/generate_report', {method:'POST'});
  const data = await res.json();
  if (data.filename) {
    const a = document.createElement('a');
    a.href = '/reports/' + data.filename;
    a.download = data.filename;
    a.click();
  }
}

// Poll every 2 seconds
setInterval(updateDashboard, 2000);
updateDashboard();
</script>
</body>
</html>
"""

# ─── ROUTES ───────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/alerts')
def api_alerts():
    data = read_shared()
    return jsonify(data.get("alerts", []))

@app.route('/api/generate_report', methods=['POST'])
def api_report():
    fname = generate_pdf_report()
    return jsonify({"filename": fname})

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(str(REPORTS_DIR), filename)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  AI-IDS SIEM DASHBOARD")
    print("  Open browser → http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
