#!/usr/bin/env python3
"""
Live Dashboard — reads results from live_results.json
written by the packet capture process.
"""

import json, os
from pathlib import Path
from datetime import datetime
from collections import Counter

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


# ─── PDF REPORT ───────────────────────────────────────────
def generate_pdf_report():
    data = read_shared()
    traffic = data.get("traffic", [])
    alerts  = data.get("alerts", [])
    total   = len(traffic)
    n_atk   = len(alerts)
    n_ben   = total - n_atk

    filename = f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = REPORTS_DIR / filename

    # Pie chart
    chart_path = REPORTS_DIR / '_chart.png'
    counts = Counter(e['label'] for e in traffic) if traffic else {"No data": 1}
    fig, ax = plt.subplots(figsize=(5, 3))
    colors = {'BENIGN': '#22c55e', 'DDoS': '#ef4444', 'PortScan': '#f59e0b', 'Bot': '#8b5cf6'}
    ax.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%', startangle=90,
           colors=[colors.get(k, '#64748b') for k in counts.keys()])
    ax.set_title("Traffic Distribution")
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

    story.append(Paragraph("Summary", heading_style))
    summary = [
        ["Metric", "Value"],
        ["Total Flows Analyzed", str(total)],
        ["Attacks Detected", str(n_atk)],
        ["Benign Flows", str(n_ben)],
        ["Detection Rate", f"{(n_atk/max(total,1))*100:.1f}%"],
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

    story.append(Paragraph("Traffic Distribution", heading_style))
    story.append(Image(str(chart_path), width=4*inch, height=2.4*inch))
    story.append(Spacer(1, 18))

    story.append(Paragraph("Attack Alerts", heading_style))
    alert_rows = [["Time", "Attack Type", "Confidence", "Dst Port"]]
    for a in alerts[-15:]:
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


# ─── HTML ─────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-IDS Live Dashboard</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;padding:16px 32px;display:flex;align-items:center;justify-content:space-between}
  header h1{font-size:1.4rem;color:#38bdf8}
  .status{display:flex;align-items:center;gap:8px;font-size:0.85rem;color:#94a3b8}
  .status-dot{width:10px;height:10px;background:#22c55e;border-radius:50%;animation:pulse 1.5s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
  .container{max-width:1400px;margin:24px auto;padding:0 24px}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
  .stat-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}
  .stat-card .label{font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:8px}
  .stat-card .value{font-size:1.8rem;font-weight:700}
  .green .value{color:#22c55e}.red .value{color:#ef4444}.blue .value{color:#38bdf8}.amber .value{color:#f59e0b}
  .main-grid{display:grid;grid-template-columns:1.6fr 1fr;gap:20px}
  .panel{background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden}
  .panel-header{padding:14px 20px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;font-size:0.85rem;font-weight:600;color:#cbd5e1;text-transform:uppercase;letter-spacing:0.5px}
  .feed-table{width:100%;border-collapse:collapse}
  .feed-table th{text-align:left;font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;padding:10px 16px;border-bottom:1px solid #334155}
  .feed-table td{padding:9px 16px;font-size:0.82rem;border-bottom:1px solid #1e293b}
  .feed-table tr:nth-child(even) td{background:#162030}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.72rem;font-weight:600;text-transform:uppercase}
  .badge-benign{background:#064e3b;color:#34d399}
  .badge-attack{background:#7f1d1d;color:#f87171}
  .alert-item{padding:12px 16px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
  .alert-item .type{font-weight:600;color:#f87171;font-size:0.85rem}
  .alert-item .time{font-size:0.72rem;color:#64748b}
  .alert-item .conf{font-size:0.72rem;color:#94a3b8}
  .no-alerts{padding:32px 16px;text-align:center;color:#64748b;font-size:0.82rem}
  .btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
  .btn-blue{background:#2563eb;color:#fff}.btn-blue:hover{background:#1d4ed8}
  .bottom-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
  code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.75rem;color:#38bdf8}
</style>
</head>
<body>
<header>
  <h1>🛡️ AI-Powered Intrusion Detection System — LIVE</h1>
  <div class="status"><span class="status-dot"></span><span id="statusText">Capturing Live Packets</span></div>
</header>
<div class="container">
  <div class="stat-grid">
    <div class="stat-card blue"><div class="label">Total Flows</div><div class="value" id="statTotal">0</div></div>
    <div class="stat-card green"><div class="label">Benign</div><div class="value" id="statBenign">0</div></div>
    <div class="stat-card red"><div class="label">Attacks</div><div class="value" id="statAttacks">0</div></div>
    <div class="stat-card amber"><div class="label">Detection Rate</div><div class="value" id="statRate">0%</div></div>
  </div>
  <div class="main-grid">
    <div class="panel">
      <div class="panel-header">
        <span>Live Traffic Feed</span>
        <button class="btn btn-blue" onclick="generateReport()">📄 PDF Report</button>
      </div>
      <div style="max-height:420px;overflow-y:auto">
        <table class="feed-table">
          <thead><tr><th>Time</th><th>Classification</th><th>Confidence</th><th>Packets</th><th>Duration</th><th>Dst Port</th></tr></thead>
          <tbody id="feedBody"></tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span>🚨 Alert Log</span>
        <span style="color:#64748b;font-size:0.7rem" id="alertCount">0 alerts</span>
      </div>
      <div id="alertList" style="max-height:420px;overflow-y:auto">
        <div class="no-alerts">Waiting for attacks...</div>
      </div>
    </div>
  </div>
  <div class="bottom-grid">
    <div class="panel">
      <div class="panel-header"><span>Model Info</span></div>
      <div style="padding:16px">
        <table style="width:100%;font-size:0.82rem">
          <tr><td style="padding:6px 0;color:#64748b">Model</td><td>Random Forest</td></tr>
          <tr><td style="padding:6px 0;color:#64748b">Dataset</td><td>CIC-IDS2017</td></tr>
          <tr><td style="padding:6px 0;color:#64748b">Accuracy</td><td style="color:#22c55e;font-weight:700">99.81%</td></tr>
          <tr><td style="padding:6px 0;color:#64748b">Classes</td><td>BENIGN, Bot, DDoS, PortScan</td></tr>
          <tr><td style="padding:6px 0;color:#64748b">Mode</td><td style="color:#38bdf8">🔴 LIVE CAPTURE</td></tr>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span>Attack Commands (run from attacker VM)</span></div>
      <div style="padding:16px;font-size:0.78rem;line-height:2;color:#94a3b8">
        <div><b style="color:#f87171">Port Scan:</b> <code>nmap -sV 192.168.68.152</code></div>
        <div><b style="color:#f87171">SYN Flood:</b> <code>sudo hping3 -S --flood 192.168.68.152</code></div>
        <div><b style="color:#f87171">UDP Flood:</b> <code>sudo hping3 --udp --flood 192.168.68.152</code></div>
        <div><b style="color:#f87171">ICMP Flood:</b> <code>sudo hping3 --icmp --flood 192.168.68.152</code></div>
      </div>
    </div>
  </div>
</div>
<script>
async function pollData() {
    try {
        const res    = await fetch('/api/traffic?limit=30');
        const rows   = await res.json();
        const sRes   = await fetch('/api/stats');
        const stats  = await sRes.json();
        const aRes   = await fetch('/api/alerts');
        const alerts = await aRes.json();

        // Stats
        document.getElementById('statTotal').textContent   = stats.total;
        document.getElementById('statBenign').textContent  = stats.benign;
        document.getElementById('statAttacks').textContent = stats.attacks;
        document.getElementById('statRate').textContent    = stats.rate + '%';

        // Feed
        const tbody = document.getElementById('feedBody');
        tbody.innerHTML = '';
        [...rows].reverse().forEach(r => {
            const isAtk = r.is_attack;
            const badge = isAtk
                ? '<span class="badge badge-attack">⚠ '+r.label+'</span>'
                : '<span class="badge badge-benign">✓ BENIGN</span>';
            tbody.innerHTML += '<tr>'
                +'<td>'+new Date(r.timestamp).toLocaleTimeString()+'</td>'
                +'<td>'+badge+'</td>'
                +'<td>'+r.confidence+'%</td>'
                +'<td>'+(r.fwd_pkts+r.bwd_pkts)+'</td>'
                +'<td>'+r.duration+'s</td>'
                +'<td>'+r.dst_port+'</td>'
                +'</tr>';
        });

        // Alerts
        document.getElementById('alertCount').textContent = alerts.length+' alerts';
        const el = document.getElementById('alertList');
        if (!alerts.length) { el.innerHTML='<div class="no-alerts">Waiting for attacks...</div>'; return; }
        el.innerHTML = '';
        [...alerts].slice(-15).reverse().forEach(a => {
            el.innerHTML += '<div class="alert-item">'
                +'<div><div class="type">⚠ '+a.label+'</div>'
                +'<div class="conf">Confidence: '+a.confidence+'% | Port: '+a.dst_port+'</div></div>'
                +'<div class="time">'+new Date(a.timestamp).toLocaleTimeString()+'</div>'
                +'</div>';
        });
    } catch(e) { console.error(e); }
}

async function generateReport() {
    const res  = await fetch('/api/generate_report', {method:'POST'});
    const data = await res.json();
    if (data.filename) {
        const a = document.createElement('a');
        a.href = '/reports/'+data.filename;
        a.download = data.filename;
        a.click();
    }
}

setInterval(pollData, 2000);
pollData();
</script>
</body>
</html>
"""

# ─── ROUTES ───────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/traffic')
def api_traffic():
    data  = read_shared()
    limit = request.args.get('limit', 30, type=int)
    return jsonify(data.get("traffic", [])[-limit:])

@app.route('/api/alerts')
def api_alerts():
    data = read_shared()
    return jsonify(data.get("alerts", []))

@app.route('/api/stats')
def api_stats():
    data    = read_shared()
    traffic = data.get("traffic", [])
    alerts  = data.get("alerts", [])
    total   = len(traffic)
    attacks = len(alerts)
    return jsonify({
        "total": total,
        "benign": total - attacks,
        "attacks": attacks,
        "rate": round((attacks / max(total, 1)) * 100, 1)
    })

@app.route('/api/generate_report', methods=['POST'])
def api_report():
    fname = generate_pdf_report()
    return jsonify({"filename": fname})

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(str(REPORTS_DIR), filename)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  AI-IDS LIVE DASHBOARD")
    print("  Open browser → http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
