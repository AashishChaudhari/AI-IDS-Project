#!/usr/bin/env python3
"""AI-IDS Professional SIEM Dashboard - Enhanced with New Attack Types"""
import json, os, time, psutil, sys
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, jsonify, send_from_directory, Response, request

app = Flask(__name__)

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
SHARED_FILE = BASE_DIR / 'data' / 'live_results.json'
REPORTS_DIR = BASE_DIR / 'reports'
REPORTS_DIR.mkdir(exist_ok=True)
START_TIME = time.time()

def read_shared():
    try:
        with open(SHARED_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"traffic": [], "alerts": []}

def get_threat_level():
    data = read_shared()
    alerts = data.get("alerts", [])
    if not alerts:
        return "LOW", "#22c55e"
    now = datetime.now()
    recent = [a for a in alerts if (now - datetime.fromisoformat(a['timestamp'])).seconds < 300]
    if len(recent) > 20:
        return "CRITICAL", "#dc2626"
    elif len(recent) > 10:
        return "HIGH", "#ef4444"
    elif len(recent) > 5:
        return "MEDIUM", "#f59e0b"
    return "LOW", "#22c55e"

# Enhanced attack type colors
ATTACK_COLORS = {
    'DDoS': '#ef4444',
    'PortScan': '#f59e0b',
    'Bot': '#a855f7',
    'SSH-Brute-Force': '#ec4899',
    'SQL-Injection': '#dc2626',
    'XSS-Attack': '#f97316',
    'Command-Injection': '#b91c1c',
    'Web-Attack': '#ea580c',
    'Slowloris-DoS': '#e11d48',
    'Unknown-Traffic': '#64748b'
}

# HTML Templates
OVERVIEW_HTML = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<title>AI-IDS Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg-primary:#0f172a;--bg-card:#1e293b;--border-color:#334155;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--accent-blue:#3b82f6;--accent-green:#22c55e;--accent-red:#ef4444;--accent-yellow:#facc15}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',sans-serif;min-height:100vh}
.navbar{background:var(--bg-card)!important;border-bottom:2px solid var(--border-color);padding:1rem 2rem}
.navbar-brand{font-size:1.5rem;font-weight:700;color:var(--accent-blue)!important}
.nav-link{color:var(--text-secondary)!important;font-weight:500;margin:0 .5rem;transition:color .2s}
.nav-link:hover,.nav-link.active{color:var(--accent-blue)!important}
.status-badge{display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1rem;border-radius:.5rem;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent-green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.kpi-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem;position:relative;overflow:hidden}
.kpi-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px}
.kpi-card.blue::before{background:var(--accent-blue)}
.kpi-card.green::before{background:var(--accent-green)}
.kpi-card.red::before{background:var(--accent-red)}
.kpi-card.yellow::before{background:var(--accent-yellow)}
.kpi-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-secondary);margin-bottom:.5rem}
.kpi-value{font-size:2.5rem;font-weight:700;margin-bottom:.25rem}
.kpi-card.blue .kpi-value{color:var(--accent-blue)}
.kpi-card.green .kpi-value{color:var(--accent-green)}
.kpi-card.red .kpi-value{color:var(--accent-red)}
.kpi-card.yellow .kpi-value{color:var(--accent-yellow)}
.kpi-change{font-size:.875rem;color:var(--text-secondary)}
.chart-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem}
.card-header-custom{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;padding-bottom:1rem;border-bottom:1px solid var(--border-color)}
.card-title{font-size:1.125rem;font-weight:600;margin:0}
.alert-item{background:var(--bg-card);border-left:4px solid;padding:1rem;margin-bottom:.75rem;border-radius:.5rem;transition:transform .2s}
.alert-item:hover{transform:translateX(4px)}
.alert-item.critical{border-color:#dc2626;background:rgba(220,38,38,.05)}
.alert-item.high{border-color:#ef4444;background:rgba(239,68,68,.05)}
.alert-item.medium{border-color:#f59e0b;background:rgba(245,158,11,.05)}
.alert-item.low{border-color:#22c55e;background:rgba(34,197,94,.05)}
.badge-attack{padding:.375rem .75rem;border-radius:.375rem;font-size:.75rem;font-weight:600}
.badge-ddos{background:rgba(239,68,68,.2);color:#ef4444}
.badge-portscan{background:rgba(245,158,11,.2);color:#f59e0b}
.badge-bot{background:rgba(168,85,247,.2);color:#a855f7}
.badge-ssh-brute-force{background:rgba(236,72,153,.2);color:#ec4899}
.badge-sql-injection{background:rgba(220,38,38,.2);color:#dc2626}
.badge-xss-attack{background:rgba(249,115,22,.2);color:#f97316}
.badge-command-injection{background:rgba(185,28,28,.2);color:#b91c1c}
.badge-web-attack{background:rgba(234,88,12,.2);color:#ea580c}
.badge-slowloris-dos{background:rgba(225,29,72,.2);color:#e11d48}
.badge-unknown-traffic{background:rgba(100,116,139,.2);color:#64748b}
.btn-pdf{background:#dc2626;color:white;border:none;padding:.625rem 1.25rem;border-radius:.5rem;font-weight:600;transition:all .2s;cursor:pointer}
.btn-pdf:hover{background:#b91c1c;transform:translateY(-2px);box-shadow:0 4px 12px rgba(220,38,38,.4)}
.btn-pdf:disabled{opacity:.5;cursor:not-allowed}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-alt"></i> AI-IDS Professional</a>
<div class="collapse navbar-collapse">
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link active" href="/"><i class="fas fa-home"></i> Overview</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-bell"></i> Alerts</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-chart-line"></i> Analytics</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> System</a></li>
</ul>
<button class="btn-pdf me-3" onclick="generateReport()" id="pdfBtn">
<i class="fas fa-file-pdf"></i> Export PDF Report
</button>
<div class="status-badge"><span class="status-dot"></span><span>Live</span></div>
<span class="text-secondary ms-3" id="lastUpdate">--:--:--</span>
</div>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row g-4 mb-4">
<div class="col-md-3"><div class="kpi-card blue"><div class="kpi-label"><i class="fas fa-network-wired"></i> Total Packets</div><div class="kpi-value" id="totalPackets">0</div><div class="kpi-change">Since monitoring started</div></div></div>
<div class="col-md-3"><div class="kpi-card red"><div class="kpi-label"><i class="fas fa-exclamation-triangle"></i> Attacks Detected</div><div class="kpi-value" id="attacksDetected">0</div><div class="kpi-change" id="attackRate">0/min avg</div></div></div>
<div class="col-md-3"><div class="kpi-card yellow"><div class="kpi-label"><i class="fas fa-shield-alt"></i> Threat Level</div><div class="kpi-value" id="threatLevel">LOW</div><div class="kpi-change">Current assessment</div></div></div>
<div class="col-md-3"><div class="kpi-card green"><div class="kpi-label"><i class="fas fa-check-circle"></i> Model Accuracy</div><div class="kpi-value">99.8%</div><div class="kpi-change">CIC-IDS2017 tested</div></div></div>
</div>
<div class="row g-4 mb-4">
<div class="col-lg-8"><div class="chart-card"><div class="card-header-custom"><h5 class="card-title"><i class="fas fa-chart-line"></i> Real-Time Traffic Monitor</h5><span class="badge bg-primary">Live</span></div><canvas id="trafficChart" height="80"></canvas></div></div>
<div class="col-lg-4"><div class="chart-card"><div class="card-header-custom"><h5 class="card-title"><i class="fas fa-chart-pie"></i> Attack Distribution</h5></div><canvas id="distributionChart"></canvas></div></div>
</div>
<div class="row"><div class="col-12"><div class="chart-card"><div class="card-header-custom"><h5 class="card-title"><i class="fas fa-bell"></i> Recent Alerts</h5><a href="/alerts" class="btn btn-sm btn-outline-primary">View All</a></div><div id="recentAlerts"></div></div></div></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
function updateTimestamp(){document.getElementById('lastUpdate').textContent=new Date().toLocaleTimeString()}
setInterval(updateTimestamp,1000);updateTimestamp();
const trafficCtx=document.getElementById('trafficChart').getContext('2d');
const distCtx=document.getElementById('distributionChart').getContext('2d');
const trafficChart=new Chart(trafficCtx,{type:'line',data:{labels:[],datasets:[{label:'Normal',data:[],borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,0.1)',tension:0.4,fill:true},{label:'Attacks',data:[],borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,0.1)',tension:0.4,fill:true}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:true,labels:{color:'#94a3b8'}}},scales:{y:{ticks:{color:'#64748b'},grid:{color:'#1e293b'}},x:{ticks:{color:'#64748b'},grid:{color:'#1e293b'}}}}});
const distChart=new Chart(distCtx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{position:'bottom',labels:{color:'#cbd5e1',padding:10,font:{size:10}}}}}});
async function updateDashboard(){try{const res=await fetch('/api/dashboard');const data=await res.json();document.getElementById('totalPackets').textContent=data.total_packets.toLocaleString();document.getElementById('attacksDetected').textContent=data.attacks_detected;document.getElementById('attackRate').textContent=data.attack_rate+'/min avg';document.getElementById('threatLevel').textContent=data.threat_level;const tlCard=document.querySelector('.kpi-card.yellow');tlCard.className='kpi-card';if(data.threat_level==='CRITICAL'||data.threat_level==='HIGH')tlCard.classList.add('red');else if(data.threat_level==='MEDIUM')tlCard.classList.add('yellow');else tlCard.classList.add('green');trafficChart.data.labels=data.traffic_labels;trafficChart.data.datasets[0].data=data.traffic_normal;trafficChart.data.datasets[1].data=data.traffic_attacks;trafficChart.update();distChart.data.labels=data.attack_types;distChart.data.datasets[0].data=data.attack_counts;distChart.data.datasets[0].backgroundColor=data.attack_colors;distChart.update();const alertsDiv=document.getElementById('recentAlerts');if(data.recent_alerts.length===0){alertsDiv.innerHTML='<p class="text-center text-secondary py-4">No attacks detected</p>'}else{alertsDiv.innerHTML=data.recent_alerts.slice(0,5).map(a=>`<div class="alert-item ${a.severity}"><div class="d-flex justify-content-between align-items-start"><div><span class="badge-attack badge-${a.label.toLowerCase().replace(/\s/g,'-')}">${a.label}</span><span class="ms-2 text-secondary">${a.time}</span></div><span class="badge bg-secondary">${a.confidence}%</span></div><div class="mt-2 text-secondary small"><i class="fas fa-bullseye"></i> Port ${a.port} | <i class="fas fa-cube"></i> ${a.packets} pkts</div></div>`).join('')}}catch(e){console.error(e)}}
async function generateReport(){const btn=document.getElementById('pdfBtn');btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Generating...';try{const res=await fetch('/api/generate_report',{method:'POST'});const data=await res.json();if(data.filename){const a=document.createElement('a');a.href='/reports/'+data.filename;a.download=data.filename;a.click();btn.innerHTML='<i class="fas fa-check"></i> Downloaded!';setTimeout(()=>{btn.innerHTML='<i class="fas fa-file-pdf"></i> Export PDF Report';btn.disabled=false},3000)}}catch(e){console.error(e);btn.innerHTML='<i class="fas fa-times"></i> Error';setTimeout(()=>{btn.innerHTML='<i class="fas fa-file-pdf"></i> Export PDF Report';btn.disabled=false},3000)}}
setInterval(updateDashboard,3000);updateDashboard();
</script>
</body>
</html>'''

ALERTS_HTML = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<title>AI-IDS - Alerts</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
<style>
:root{--bg-primary:#0f172a;--bg-card:#1e293b;--border-color:#334155;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--accent-blue:#3b82f6}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',sans-serif}
.navbar{background:var(--bg-card)!important;border-bottom:2px solid var(--border-color);padding:1rem 2rem}
.navbar-brand{font-size:1.5rem;font-weight:700;color:var(--accent-blue)!important}
.nav-link{color:var(--text-secondary)!important;font-weight:500;margin:0 .5rem}
.nav-link:hover,.nav-link.active{color:var(--accent-blue)!important}
.chart-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem}
.card-header-custom{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;padding-bottom:1rem;border-bottom:1px solid var(--border-color)}
.table-dark{--bs-table-bg:var(--bg-card);--bs-table-border-color:var(--border-color)}
.btn-export{background:var(--accent-blue);color:white;border:none;padding:.625rem 1.25rem;border-radius:.5rem;font-weight:600}
.badge-attack{padding:.375rem .75rem;border-radius:.375rem;font-size:.75rem;font-weight:600}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-alt"></i> AI-IDS Professional</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-home"></i> Overview</a></li>
<li class="nav-item"><a class="nav-link active" href="/alerts"><i class="fas fa-bell"></i> Alerts</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-chart-line"></i> Analytics</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> System</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2><i class="fas fa-bell"></i> Alert Management</h2><p class="text-secondary">Comprehensive view of all detected threats</p></div></div>
<div class="row"><div class="col-12"><div class="chart-card">
<div class="card-header-custom"><h5 class="card-title">All Alerts</h5><button class="btn-export" onclick="exportCSV()"><i class="fas fa-download"></i> Export CSV</button></div>
<table id="alertsTable" class="table table-dark table-striped">
<thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Confidence</th><th>Severity</th><th>Port</th><th>Packets</th></tr></thead>
<tbody></tbody>
</table>
</div></div></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
<script>
let tbl;
async function load(){const r=await fetch('/api/all_alerts');const a=await r.json();if(tbl)tbl.destroy();document.querySelector('#alertsTable tbody').innerHTML=a.map(x=>`<tr><td>${x.time}</td><td>192.168.68.145</td><td><span class="badge-attack" style="background:${x.color}20;color:${x.color}">${x.label}</span></td><td>${x.confidence}%</td><td><span class="badge bg-${x.severity_color}">${x.severity}</span></td><td>${x.port}</td><td>${x.packets}</td></tr>`).join('');tbl=$('#alertsTable').DataTable({order:[[0,'desc']],pageLength:25})}
function exportCSV(){fetch('/api/export_alerts_csv').then(r=>r.blob()).then(b=>{const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='alerts.csv';a.click()})}
load();setInterval(load,10000);
</script>
</body>
</html>'''

ANALYTICS_HTML = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<title>AI-IDS - Analytics</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg-primary:#0f172a;--bg-card:#1e293b;--border-color:#334155;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--accent-blue:#3b82f6;--accent-green:#22c55e;--accent-yellow:#facc15}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',sans-serif;min-height:100vh}
.navbar{background:var(--bg-card)!important;border-bottom:2px solid var(--border-color);padding:1rem 2rem}
.navbar-brand{font-size:1.5rem;font-weight:700;color:var(--accent-blue)!important}
.nav-link{color:var(--text-secondary)!important;font-weight:500;margin:0 .5rem}
.nav-link:hover,.nav-link.active{color:var(--accent-blue)!important}
.kpi-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem;position:relative;overflow:hidden}
.kpi-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px}
.kpi-card.green::before{background:var(--accent-green)}
.kpi-card.blue::before{background:var(--accent-blue)}
.kpi-card.yellow::before{background:var(--accent-yellow)}
.kpi-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-secondary);margin-bottom:.5rem}
.kpi-value{font-size:2.5rem;font-weight:700;margin-bottom:.25rem}
.kpi-card.green .kpi-value{color:var(--accent-green)}
.kpi-card.blue .kpi-value{color:var(--accent-blue)}
.kpi-card.yellow .kpi-value{color:var(--accent-yellow)}
.kpi-change{font-size:.875rem;color:var(--text-secondary)}
.chart-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem}
.table-dark{--bs-table-bg:var(--bg-card);--bs-table-border-color:var(--border-color)}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-alt"></i> AI-IDS Professional</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-home"></i> Overview</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-bell"></i> Alerts</a></li>
<li class="nav-item"><a class="nav-link active" href="/analytics"><i class="fas fa-chart-line"></i> Analytics</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> System</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2><i class="fas fa-chart-line"></i> Model Analytics</h2><p class="text-secondary">Performance metrics and live attack statistics</p></div></div>
<div class="row g-4 mb-4">
<div class="col-md-3"><div class="kpi-card green"><div class="kpi-label">Overall Accuracy</div><div class="kpi-value">99.81%</div><div class="kpi-change">94,110 test samples</div></div></div>
<div class="col-md-3"><div class="kpi-card blue"><div class="kpi-label">Detection Types</div><div class="kpi-value" id="detectionTypes">8</div><div class="kpi-change">Hybrid + ML detection</div></div></div>
<div class="col-md-3"><div class="kpi-card blue"><div class="kpi-label">Recall</div><div class="kpi-value">99.81%</div><div class="kpi-change">True positive rate</div></div></div>
<div class="col-md-3"><div class="kpi-card yellow"><div class="kpi-label">False Positive Rate</div><div class="kpi-value">0.19%</div><div class="kpi-change">179 / 94,110</div></div></div>
</div>
<div class="row g-4">
<div class="col-lg-6"><div class="chart-card"><h5 class="mb-3">Live Attack Distribution</h5><canvas id="liveAttacks" height="300"></canvas></div></div>
<div class="col-lg-6"><div class="chart-card"><h5 class="mb-3">Detection Methods</h5>
<table class="table table-dark table-sm">
<thead><tr><th>Attack Type</th><th>Detection Method</th><th>Threshold</th></tr></thead>
<tbody>
<tr><td>DDoS</td><td>Rate-based</td><td>&gt;100 pkt/s</td></tr>
<tr><td>PortScan</td><td>Port counting</td><td>10+ ports</td></tr>
<tr><td>SSH Brute Force</td><td>Attempt tracking</td><td>10+ attempts/10s</td></tr>
<tr><td>SQL Injection</td><td>Pattern matching</td><td>SQL keywords</td></tr>
<tr><td>XSS</td><td>Pattern matching</td><td>Script tags</td></tr>
<tr><td>Cmd Injection</td><td>Pattern matching</td><td>Shell commands</td></tr>
<tr><td>Slowloris</td><td>Connection tracking</td><td>20+ slow conn</td></tr>
<tr><td>Unknown</td><td>ML confidence</td><td>&lt;60%</td></tr>
</tbody>
</table>
</div></div>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
const liveCtx=document.getElementById('liveAttacks').getContext('2d');
const liveChart=new Chart(liveCtx,{type:'bar',data:{labels:[],datasets:[{label:'Attacks Detected',data:[],backgroundColor:[]}]},options:{responsive:true,indexAxis:'y',scales:{y:{ticks:{color:'#64748b'},grid:{color:'#1e293b'}},x:{ticks:{color:'#64748b'},grid:{color:'#1e293b'}}},plugins:{legend:{display:false}}}});
async function updateLive(){try{const r=await fetch('/api/dashboard');const d=await r.json();liveChart.data.labels=d.attack_types;liveChart.data.datasets[0].data=d.attack_counts;liveChart.data.datasets[0].backgroundColor=d.attack_colors;liveChart.update();document.getElementById('detectionTypes').textContent=d.attack_types.length}catch(e){}}
setInterval(updateLive,5000);updateLive();
</script>
</body>
</html>'''

SETTINGS_HTML = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<title>AI-IDS - System</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<style>
:root{--bg-primary:#0f172a;--bg-card:#1e293b;--border-color:#334155;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--accent-blue:#3b82f6}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',sans-serif;min-height:100vh}
.navbar{background:var(--bg-card)!important;border-bottom:2px solid var(--border-color);padding:1rem 2rem}
.navbar-brand{font-size:1.5rem;font-weight:700;color:var(--accent-blue)!important}
.nav-link{color:var(--text-secondary)!important;font-weight:500;margin:0 .5rem}
.nav-link:hover,.nav-link.active{color:var(--accent-blue)!important}
.chart-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:1rem;padding:1.5rem}
.table-dark{--bs-table-bg:var(--bg-card);--bs-table-border-color:var(--border-color)}
.progress{height:10px;border-radius:5px;background:var(--bg-primary)}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-alt"></i> AI-IDS Professional</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-home"></i> Overview</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-bell"></i> Alerts</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-chart-line"></i> Analytics</a></li>
<li class="nav-item"><a class="nav-link active" href="/settings"><i class="fas fa-cog"></i> System</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2><i class="fas fa-cog"></i> System Status</h2><p class="text-secondary">Monitor system health and configuration</p></div></div>
<div class="row g-4">
<div class="col-lg-6"><div class="chart-card"><h5 class="mb-3"><i class="fas fa-microchip"></i> System Resources</h5>
<div class="mb-4"><label class="mb-2 fw-bold">CPU Usage</label><div class="progress"><div class="progress-bar bg-info" id="cpuBar" style="width:0%"></div></div><small class="text-secondary" id="cpuText">0%</small></div>
<div class="mb-4"><label class="mb-2 fw-bold">Memory Usage</label><div class="progress"><div class="progress-bar bg-warning" id="memBar" style="width:0%"></div></div><small class="text-secondary" id="memText">0%</small></div>
<div><label class="mb-2 fw-bold">Disk Usage</label><div class="progress"><div class="progress-bar bg-success" id="diskBar" style="width:0%"></div></div><small class="text-secondary" id="diskText">0%</small></div>
</div></div>
<div class="col-lg-6"><div class="chart-card"><h5 class="mb-3"><i class="fas fa-info-circle"></i> Configuration</h5>
<table class="table table-dark table-sm">
<tr><td><strong>Model Type</strong></td><td class="text-end">Random Forest</td></tr>
<tr><td><strong>Detection Mode</strong></td><td class="text-end">Hybrid (ML + Signature)</td></tr>
<tr><td><strong>Attack Types</strong></td><td class="text-end">8 types</td></tr>
<tr><td><strong>Dataset</strong></td><td class="text-end">CIC-IDS2017</td></tr>
<tr><td><strong>Test Accuracy</strong></td><td class="text-end">99.81%</td></tr>
<tr><td><strong>Interface</strong></td><td class="text-end">eth0</td></tr>
<tr><td><strong>Email Alerts</strong></td><td class="text-end">Configured</td></tr>
<tr><td><strong>Uptime</strong></td><td class="text-end" id="uptime">0m</td></tr>
</table>
</div></div>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
async function updateSystemStats(){const res=await fetch('/api/system_stats');const data=await res.json();document.getElementById('cpuBar').style.width=data.cpu+'%';document.getElementById('cpuText').textContent=data.cpu+'%';document.getElementById('memBar').style.width=data.memory+'%';document.getElementById('memText').textContent=data.memory+'%';document.getElementById('diskBar').style.width=data.disk+'%';document.getElementById('diskText').textContent=data.disk+'%';document.getElementById('uptime').textContent=data.uptime}
setInterval(updateSystemStats,2000);updateSystemStats();
</script>
</body>
</html>'''

# Routes
@app.route('/')
def index():
    return OVERVIEW_HTML

@app.route('/alerts')
def alerts_page():
    return ALERTS_HTML

@app.route('/analytics')
def analytics_page():
    return ANALYTICS_HTML

@app.route('/settings')
def settings_page():
    return SETTINGS_HTML

@app.route('/api/dashboard')
def api_dashboard():
    from collections import Counter
    data = read_shared()
    alerts = data.get("alerts", [])
    traffic = data.get("traffic", [])
    
    total_packets = sum(t['fwd_pkts'] + t['bwd_pkts'] for t in traffic)
    attacks = len(alerts)
    
    if alerts:
        first = datetime.fromisoformat(alerts[0]['timestamp'])
        last = datetime.fromisoformat(alerts[-1]['timestamp'])
        minutes = max((last - first).seconds / 60, 1)
        rate = round(attacks / minutes, 1)
    else:
        rate = 0
    
    level, color = get_threat_level()
    
    now = datetime.now()
    labels = [(now - timedelta(minutes=i)).strftime('%H:%M') for i in range(59, -1, -1)]
    
    attack_counts_timeline = [0] * 60
    normal_counts = [0] * 60
    
    for t in traffic[-200:]:
        ts = datetime.fromisoformat(t['timestamp'])
        mins_ago = int((now - ts).seconds / 60)
        if mins_ago < 60:
            if t['is_attack']:
                attack_counts_timeline[59 - mins_ago] += 1
            else:
                normal_counts[59 - mins_ago] += 1
    
    # Count each attack type
    attack_type_counter = Counter(a['label'] for a in alerts)
    
    # Build distribution data
    attack_types = list(attack_type_counter.keys())
    attack_counts = list(attack_type_counter.values())
    attack_colors = [ATTACK_COLORS.get(t, '#64748b') for t in attack_types]
    
    # Recent alerts with severity
    recent = []
    for a in alerts[-10:]:
        conf = a['confidence']
        if conf >= 95:
            severity = 'critical'
        elif conf >= 85:
            severity = 'high'
        elif conf >= 75:
            severity = 'medium'
        else:
            severity = 'low'
        
        recent.append({
            'label': a['label'],
            'time': datetime.fromisoformat(a['timestamp']).strftime('%H:%M:%S'),
            'confidence': conf,
            'port': a.get('dst_port', '—'),
            'packets': a['fwd_pkts'] + a['bwd_pkts'],
            'severity': severity
        })
    
    return jsonify({
        'total_packets': total_packets,
        'attacks_detected': attacks,
        'attack_rate': rate,
        'threat_level': level,
        'traffic_labels': labels,
        'traffic_normal': normal_counts,
        'traffic_attacks': attack_counts_timeline,
        'attack_types': attack_types,
        'attack_counts': attack_counts,
        'attack_colors': attack_colors,
        'recent_alerts': recent
    })

@app.route('/api/all_alerts')
def api_all_alerts():
    data = read_shared()
    alerts = data.get("alerts", [])
    result = []
    for a in alerts:
        conf = a['confidence']
        if conf >= 95:
            severity = 'CRITICAL'
            color = 'danger'
        elif conf >= 85:
            severity = 'HIGH'
            color = 'warning'
        else:
            severity = 'MEDIUM'
            color = 'info'
        
        result.append({
            'time': datetime.fromisoformat(a['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'label': a['label'],
            'confidence': a['confidence'],
            'severity': severity,
            'severity_color': color,
            'port': a.get('dst_port', '—'),
            'packets': a['fwd_pkts'] + a['bwd_pkts'],
            'color': ATTACK_COLORS.get(a['label'], '#64748b')
        })
    return jsonify(result)

@app.route('/api/export_alerts_csv')
def api_export_csv():
    data = read_shared()
    alerts = data.get("alerts", [])
    csv = "Timestamp,Attack Type,Confidence,Port,Packets\n"
    for a in alerts:
        csv += f"{a['timestamp']},{a['label']},{a['confidence']},{a.get('dst_port','')},{a['fwd_pkts']+a['bwd_pkts']}\n"
    return Response(csv, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=alerts.csv'})

@app.route('/api/system_stats')
def api_system_stats():
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    uptime_seconds = int(time.time() - START_TIME)
    if uptime_seconds < 60:
        uptime_str = f"{uptime_seconds}s"
    elif uptime_seconds < 3600:
        uptime_str = f"{uptime_seconds // 60}m"
    else:
        uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
    return jsonify({'cpu': round(cpu, 1),'memory': round(mem, 1),'disk': round(disk, 1),'uptime': uptime_str})

@app.route('/api/generate_report', methods=['POST'])
def api_generate_report():
    sys.path.insert(0, str(Path(__file__).parent))
    from report_generator import IDSReportGenerator
    data = read_shared()
    alerts = data.get("alerts", [])
    generator = IDSReportGenerator(alerts)
    filename = generator.generate_report()
    return jsonify({"filename": filename})

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(str(REPORTS_DIR), filename)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  AI-IDS PROFESSIONAL DASHBOARD")
    print("  http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
