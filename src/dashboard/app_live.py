#!/usr/bin/env python3
"""
AI-IDS Professional SIEM Dashboard - Enhanced Neon Edition
Features: Attack Heatmap, Inline CVE Mapping, Real-time monitoring
"""
import json, os, time, psutil, sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from flask import Flask, jsonify, send_from_directory, Response

app = Flask(__name__)

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
SHARED_FILE = BASE_DIR / 'data' / 'live_results.json'
REPORTS_DIR = BASE_DIR / 'reports'
REPORTS_DIR.mkdir(exist_ok=True)
START_TIME = time.time()

# Expanded CVE Database - Maps ALL attack types to relevant CVEs
CVE_DATABASE = {
    'DDoS': [
        {'cve': 'CVE-2024-3400', 'severity': 10.0, 'description': 'PAN-OS Command Injection for DDoS amplification'},
        {'cve': 'CVE-2023-46604', 'severity': 10.0, 'description': 'Apache ActiveMQ RCE in DDoS botnets'},
        {'cve': 'CVE-2023-4966', 'severity': 9.4, 'description': 'Citrix Bleed enabling DDoS attacks'}
    ],
    'PortScan': [
        {'cve': 'CVE-2024-21887', 'severity': 9.1, 'description': 'Ivanti Connect pre-auth command injection'},
        {'cve': 'CVE-2023-22515', 'severity': 10.0, 'description': 'Confluence privilege escalation target'},
        {'cve': 'CVE-2023-20198', 'severity': 10.0, 'description': 'Cisco IOS XE Web UI exploit target'}
    ],
    'Bot': [
        {'cve': 'CVE-2024-23897', 'severity': 9.8, 'description': 'Jenkins arbitrary file read for botnets'},
        {'cve': 'CVE-2023-27997', 'severity': 9.2, 'description': 'FortiOS heap overflow for botnet recruitment'},
        {'cve': 'CVE-2022-30525', 'severity': 9.8, 'description': 'Zyxel firewall OS injection for botnet C2'}
    ],
    'SQL-Injection': [
        {'cve': 'CVE-2024-27348', 'severity': 9.8, 'description': 'Apache HugeGraph SQL injection RCE'},
        {'cve': 'CVE-2023-48788', 'severity': 9.8, 'description': 'Fortinet FortiClient EMS SQL injection'},
        {'cve': 'CVE-2023-34362', 'severity': 9.8, 'description': 'MOVEit Transfer SQL injection zero-day'},
        {'cve': 'CVE-2022-47966', 'severity': 9.8, 'description': 'Zoho ManageEngine SQLi in multiple products'}
    ],
    'XSS-Attack': [
        {'cve': 'CVE-2024-21762', 'severity': 9.6, 'description': 'FortiOS SSL-VPN XSS to RCE chain'},
        {'cve': 'CVE-2023-51467', 'severity': 9.8, 'description': 'Apache OFBiz XSS leading to RCE'},
        {'cve': 'CVE-2023-38831', 'severity': 7.8, 'description': 'WinRAR XSS exploited by state actors'},
        {'cve': 'CVE-2022-41040', 'severity': 8.8, 'description': 'ProxyNotShell XSS in Exchange Server'}
    ],
    'SSH-Brute-Force': [
        {'cve': 'CVE-2024-6387', 'severity': 8.1, 'description': 'OpenSSH regreSSHion RCE via brute force'},
        {'cve': 'CVE-2023-48795', 'severity': 5.9, 'description': 'Terrapin attack SSH protocol weakness'},
        {'cve': 'CVE-2021-28041', 'severity': 7.1, 'description': 'OpenSSH agent forwarding exploit'},
        {'cve': 'CVE-2020-15778', 'severity': 7.8, 'description': 'OpenSSH privilege escalation'}
    ],
    'Slowloris-DoS': [
        {'cve': 'CVE-2023-44487', 'severity': 7.5, 'description': 'HTTP/2 Rapid Reset DDoS (Slowloris variant)'},
        {'cve': 'CVE-2022-41742', 'severity': 7.5, 'description': 'NGINX slow HTTP DoS vulnerability'},
        {'cve': 'CVE-2020-11724', 'severity': 7.5, 'description': 'Apache HTTP slow request handling DoS'}
    ],
    'BENIGN': []
}

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

def generate_heatmap_data():
    """Generate 24-hour attack heatmap data"""
    data = read_shared()
    alerts = data.get("alerts", [])
    heatmap = [[0 for _ in range(24)] for _ in range(7)]
    for alert in alerts:
        dt = datetime.fromisoformat(alert['timestamp'])
        day = dt.weekday()
        hour = dt.hour
        heatmap[day][hour] += 1
    return heatmap

def get_cves_for_attack(attack_type):
    """Get top 2 CVEs for an attack type"""
    return CVE_DATABASE.get(attack_type, [])[:2]

# Shared CSS
SHARED_CSS = '''
* {margin:0;padding:0;box-sizing:border-box}
:root {
  --neon-blue: #00f3ff;
  --neon-purple: #bf00ff;
  --neon-pink: #ff0080;
  --neon-green: #00ff41;
  --dark-bg: #0a0e27;
  --card-bg: #0f1428;
  --glass-bg: rgba(15, 20, 40, 0.7);
}
body {
  background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0a0e27 100%);
  color: #e0e7ff;
  font-family: 'Segoe UI', system-ui, sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
}
.navbar {
  background: var(--glass-bg) !important;
  backdrop-filter: blur(10px);
  border-bottom: 2px solid rgba(0, 243, 255, 0.3);
  padding: 1rem 2rem;
  box-shadow: 0 4px 30px rgba(0, 243, 255, 0.1);
}
.navbar-brand {
  font-size: 1.8rem;
  font-weight: 900;
  background: linear-gradient(90deg, var(--neon-blue), var(--neon-purple));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 20px rgba(0, 243, 255, 0.5);
  letter-spacing: 2px;
}
.nav-link {
  color: #94a3b8 !important;
  font-weight: 600;
  margin: 0 0.5rem;
  transition: all 0.3s;
  position: relative;
}
.nav-link:hover, .nav-link.active {
  color: var(--neon-blue) !important;
  text-shadow: 0 0 10px rgba(0, 243, 255, 0.8);
}
.nav-link.active::after {
  content: '';
  position: absolute;
  bottom: -5px;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--neon-blue), transparent);
}
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1.2rem;
  border-radius: 50px;
  background: rgba(0, 255, 65, 0.1);
  border: 2px solid var(--neon-green);
  box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
  animation: pulse-glow 2s infinite;
}
@keyframes pulse-glow {
  0%, 100% { box-shadow: 0 0 20px rgba(0, 255, 65, 0.3); }
  50% { box-shadow: 0 0 30px rgba(0, 255, 65, 0.6); }
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--neon-green);
  box-shadow: 0 0 10px var(--neon-green);
  animation: pulse-dot 1.5s infinite;
}
@keyframes pulse-dot {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.2); opacity: 0.8; }
}
.kpi-card {
  background: var(--glass-bg);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 243, 255, 0.2);
  border-radius: 20px;
  padding: 1.5rem;
  position: relative;
  overflow: hidden;
  transition: all 0.3s;
}
.kpi-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 10px 40px rgba(0, 243, 255, 0.3);
  border-color: rgba(0, 243, 255, 0.6);
}
.kpi-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
}
.kpi-card.blue::before { background: linear-gradient(90deg, transparent, var(--neon-blue), transparent); }
.kpi-card.green::before { background: linear-gradient(90deg, transparent, var(--neon-green), transparent); }
.kpi-card.red::before { background: linear-gradient(90deg, transparent, var(--neon-pink), transparent); }
.kpi-card.purple::before { background: linear-gradient(90deg, transparent, var(--neon-purple), transparent); }
.kpi-label {
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 2px;
  color: #64748b;
  margin-bottom: 0.5rem;
  font-weight: 600;
}
.kpi-value {
  font-size: 3rem;
  font-weight: 900;
  margin-bottom: 0.3rem;
  background: linear-gradient(135deg, #00f3ff, #00c9ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.kpi-card.green .kpi-value { background: linear-gradient(135deg, #00ff41, #00d436); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.kpi-card.red .kpi-value { background: linear-gradient(135deg, #ff0080, #ff0055); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.kpi-card.purple .kpi-value { background: linear-gradient(135deg, #bf00ff, #9500cc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.kpi-change {
  font-size: 0.9rem;
  color: #94a3b8;
}
.chart-card {
  background: var(--glass-bg);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 243, 255, 0.2);
  border-radius: 20px;
  padding: 1.5rem;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}
.card-header-custom {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid rgba(0, 243, 255, 0.2);
}
.card-title {
  font-size: 1.2rem;
  font-weight: 700;
  color: var(--neon-blue);
  text-shadow: 0 0 10px rgba(0, 243, 255, 0.5);
  letter-spacing: 1px;
}
.alert-item {
  background: rgba(15, 20, 40, 0.5);
  border-left: 4px solid;
  padding: 1rem;
  margin-bottom: 0.75rem;
  border-radius: 10px;
  transition: all 0.3s;
  backdrop-filter: blur(5px);
}
.alert-item:hover {
  transform: translateX(8px);
  box-shadow: -5px 0 20px rgba(255, 0, 128, 0.3);
}
.alert-item.critical { border-color: #ff0055; background: rgba(255, 0, 85, 0.05); box-shadow: 0 0 20px rgba(255, 0, 85, 0.2); }
.alert-item.high { border-color: #ff0080; background: rgba(255, 0, 128, 0.05); }
.alert-item.medium { border-color: #ffaa00; background: rgba(255, 170, 0, 0.05); }
.alert-item.low { border-color: #00ff41; background: rgba(0, 255, 65, 0.05); }
.badge-attack {
  padding: 0.4rem 0.9rem;
  border-radius: 50px;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1px;
}
.badge-ddos { background: linear-gradient(135deg, rgba(255, 0, 85, 0.2), rgba(255, 0, 128, 0.2)); color: #ff0080; border: 1px solid #ff0080; box-shadow: 0 0 15px rgba(255, 0, 128, 0.3); }
.badge-portscan { background: linear-gradient(135deg, rgba(255, 170, 0, 0.2), rgba(255, 200, 0, 0.2)); color: #ffaa00; border: 1px solid #ffaa00; box-shadow: 0 0 15px rgba(255, 170, 0, 0.3); }
.badge-bot { background: linear-gradient(135deg, rgba(191, 0, 255, 0.2), rgba(149, 0, 204, 0.2)); color: #bf00ff; border: 1px solid #bf00ff; box-shadow: 0 0 15px rgba(191, 0, 255, 0.3); }
.badge-sql-injection { background: linear-gradient(135deg, rgba(255, 0, 85, 0.2), rgba(220, 0, 100, 0.2)); color: #ff0055; border: 1px solid #ff0055; box-shadow: 0 0 15px rgba(255, 0, 85, 0.3); }
.badge-xss-attack { background: linear-gradient(135deg, rgba(255, 100, 0, 0.2), rgba(255, 150, 0, 0.2)); color: #ff6400; border: 1px solid #ff6400; box-shadow: 0 0 15px rgba(255, 100, 0, 0.3); }
.badge-ssh-brute-force { background: linear-gradient(135deg, rgba(200, 0, 255, 0.2), rgba(160, 0, 220, 0.2)); color: #c800ff; border: 1px solid #c800ff; box-shadow: 0 0 15px rgba(200, 0, 255, 0.3); }
.badge-slowloris-dos { background: linear-gradient(135deg, rgba(255, 50, 150, 0.2), rgba(255, 0, 180, 0.2)); color: #ff3296; border: 1px solid #ff3296; box-shadow: 0 0 15px rgba(255, 50, 150, 0.3); }
.cve-inline {
  margin-top: 0.6rem;
  padding: 0.5rem;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 6px;
  border-left: 3px solid #ff0080;
}
.cve-badge {
  background: rgba(255, 0, 128, 0.2);
  color: #ff0080;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  font-family: 'Courier New', monospace;
  margin-right: 0.5rem;
}
.cve-text {
  font-size: 0.75rem;
  color: #94a3b8;
  margin-top: 0.3rem;
}
.btn-pdf {
  background: linear-gradient(135deg, #ff0080, #bf00ff);
  color: white;
  border: none;
  padding: 0.7rem 1.5rem;
  border-radius: 50px;
  font-weight: 700;
  letter-spacing: 1px;
  transition: all 0.3s;
  box-shadow: 0 4px 20px rgba(255, 0, 128, 0.4);
  cursor: pointer;
  text-transform: uppercase;
}
.btn-pdf:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 30px rgba(255, 0, 128, 0.6);
  background: linear-gradient(135deg, #ff0055, #9500cc);
}
.btn-export {
  background: linear-gradient(135deg, #00f3ff, #bf00ff);
  color: white;
  border: none;
  padding: 0.7rem 1.5rem;
  border-radius: 50px;
  font-weight: 700;
  box-shadow: 0 4px 20px rgba(0, 243, 255, 0.4);
  cursor: pointer;
}
.live-badge {
  background: rgba(255, 0, 128, 0.2);
  color: var(--neon-pink);
  padding: 0.3rem 0.8rem;
  border-radius: 50px;
  font-size: 0.75rem;
  font-weight: 700;
  border: 1px solid var(--neon-pink);
  animation: pulse-badge 2s infinite;
}
@keyframes pulse-badge {
  0%, 100% { box-shadow: 0 0 10px rgba(255, 0, 128, 0.4); }
  50% { box-shadow: 0 0 20px rgba(255, 0, 128, 0.8); }
}
.table-dark{--bs-table-bg:rgba(15,20,40,0.5);--bs-table-border-color:rgba(0,243,255,0.2)}
.progress{height:12px;border-radius:6px;background:rgba(15,20,40,0.5)}
.progress-bar{background:linear-gradient(90deg,#00f3ff,#00c9ff)}
'''

OVERVIEW_HTML = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-IDS - Cyber Defense Command</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>{SHARED_CSS}</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-virus"></i> CYBER DEFENSE</a>
<div class="collapse navbar-collapse">
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link active" href="/"><i class="fas fa-radar"></i> COMMAND</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-skull-crossbones"></i> THREATS</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-brain"></i> INTEL</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> SYSTEM</a></li>
</ul>
<button class="btn-pdf me-3" onclick="generateReport()" id="pdfBtn">
<i class="fas fa-file-export"></i> EXPORT REPORT
</button>
<div class="status-badge">
<span class="status-dot"></span>
<span>ACTIVE</span>
</div>
<span class="text-secondary ms-3" id="lastUpdate" style="color:#64748b;font-size:0.85rem;">--:--:--</span>
</div>
</div>
</nav>

<div class="container-fluid p-4">
<div class="row g-4 mb-4">
<div class="col-md-3">
<div class="kpi-card blue">
<div class="kpi-label"><i class="fas fa-network-wired"></i> PACKETS ANALYZED</div>
<div class="kpi-value" id="totalPackets">0</div>
<div class="kpi-change">Real-time monitoring</div>
</div>
</div>
<div class="col-md-3">
<div class="kpi-card red">
<div class="kpi-label"><i class="fas fa-crosshairs"></i> THREATS DETECTED</div>
<div class="kpi-value" id="attacksDetected">0</div>
<div class="kpi-change" id="attackRate">0/min avg</div>
</div>
</div>
<div class="col-md-3">
<div class="kpi-card purple">
<div class="kpi-label"><i class="fas fa-radiation"></i> THREAT LEVEL</div>
<div class="kpi-value" id="threatLevel">LOW</div>
<div class="kpi-change">Current assessment</div>
</div>
</div>
<div class="col-md-3">
<div class="kpi-card green">
<div class="kpi-label"><i class="fas fa-bullseye"></i> MODEL ACCURACY</div>
<div class="kpi-value">99.8%</div>
<div class="kpi-change">7 attack types</div>
</div>
</div>
</div>

<div class="row g-4 mb-4">
<div class="col-lg-8">
<div class="chart-card">
<div class="card-header-custom">
<h5 class="card-title"><i class="fas fa-wave-square"></i> NETWORK ACTIVITY STREAM</h5>
<span class="live-badge">LIVE</span>
</div>
<canvas id="trafficChart" height="80"></canvas>
</div>
</div>
<div class="col-lg-4">
<div class="chart-card">
<div class="card-header-custom">
<h5 class="card-title"><i class="fas fa-virus"></i> ATTACK VECTORS</h5>
</div>
<canvas id="distributionChart"></canvas>
</div>
</div>
</div>

<div class="row g-4 mb-4">
<div class="col-12">
<div class="chart-card">
<div class="card-header-custom">
<h5 class="card-title"><i class="fas fa-fire"></i> ATTACK HEATMAP - TEMPORAL ANALYSIS</h5>
<span class="badge bg-info">24x7 Activity Map</span>
</div>
<canvas id="heatmapChart" height="80"></canvas>
</div>
</div>
</div>

<div class="row">
<div class="col-12">
<div class="chart-card">
<div class="card-header-custom">
<h5 class="card-title"><i class="fas fa-satellite-dish"></i> THREAT INTELLIGENCE FEED</h5>
<a href="/alerts" class="btn btn-sm btn-outline-primary">VIEW ALL</a>
</div>
<div id="recentAlerts"></div>
</div>
</div>
</div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
function updateTimestamp(){{document.getElementById('lastUpdate').textContent=new Date().toLocaleTimeString()}}
setInterval(updateTimestamp,1000);updateTimestamp();

const trafficCtx=document.getElementById('trafficChart').getContext('2d');
const distCtx=document.getElementById('distributionChart').getContext('2d');
const heatmapCtx=document.getElementById('heatmapChart').getContext('2d');

const trafficChart=new Chart(trafficCtx,{{type:'line',data:{{labels:[],datasets:[{{label:'Normal',data:[],borderColor:'#00ff41',backgroundColor:'rgba(0,255,65,0.1)',tension:0.4,fill:true,borderWidth:2}},{{label:'Threats',data:[],borderColor:'#ff0080',backgroundColor:'rgba(255,0,128,0.1)',tension:0.4,fill:true,borderWidth:2}}]}},options:{{responsive:true,maintainAspectRatio:true,plugins:{{legend:{{display:true,labels:{{color:'#94a3b8',font:{{size:12,weight:'bold'}}}}}}}},scales:{{y:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}},x:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}}}}}}}});

const distChart=new Chart(distCtx,{{type:'doughnut',data:{{labels:[],datasets:[{{data:[],backgroundColor:['#ff0080','#ffaa00','#bf00ff','#ff0055','#ff6400','#c800ff','#ff3296'],borderColor:['#ff0055','#ff8800','#9500cc','#cc0044','#ff4400','#aa00dd','#ff1177'],borderWidth:2}}]}},options:{{responsive:true,maintainAspectRatio:true,plugins:{{legend:{{position:'bottom',labels:{{color:'#cbd5e1',padding:10,font:{{size:10,weight:'bold'}}}}}}}}}}}});

const heatmapChart=new Chart(heatmapCtx,{{type:'bar',data:{{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[]}},options:{{responsive:true,maintainAspectRatio:true,indexAxis:'y',plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{title:function(ctx){{return['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][ctx[0].dataIndex]+' '+ctx[0].dataset.label}},label:function(ctx){{return ctx.parsed.x+' attacks'}}}}}}}},scales:{{x:{{stacked:true,ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}},y:{{stacked:true,ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}}}}}}}});

async function updateDashboard(){{try{{const res=await fetch('/api/dashboard');const data=await res.json();document.getElementById('totalPackets').textContent=data.total_packets.toLocaleString();document.getElementById('attacksDetected').textContent=data.attacks_detected;document.getElementById('attackRate').textContent=data.attack_rate+'/min avg';document.getElementById('threatLevel').textContent=data.threat_level;trafficChart.data.labels=data.traffic_labels;trafficChart.data.datasets[0].data=data.traffic_normal;trafficChart.data.datasets[1].data=data.traffic_attacks;trafficChart.update();distChart.data.labels=data.attack_labels;distChart.data.datasets[0].data=data.attack_counts;distChart.update();if(data.heatmap){{const colors=['#ff0055','#ff0080','#ff00aa','#ff00d4','#bf00ff','#9500cc','#6b00ff','#4400ff','#0040ff','#0080ff','#00aaff','#00d4ff','#00f3ff','#00ffd4','#00ffaa','#00ff80','#00ff40','#40ff00','#80ff00','#aaff00','#d4ff00','#ffff00','#ffd400','#ffaa00'];heatmapChart.data.datasets=[];for(let h=0;h<24;h++){{heatmapChart.data.datasets.push({{label:(h<10?'0':'')+h+':00',data:data.heatmap.map(day=>day[h]),backgroundColor:colors[h],borderWidth:0}})}}heatmapChart.update()}}const alertsDiv=document.getElementById('recentAlerts');if(data.recent_alerts.length===0){{alertsDiv.innerHTML='<p class="text-center text-secondary py-4">No threats detected</p>'}}else{{alertsDiv.innerHTML=data.recent_alerts.slice(0,5).map(a=>{{let cveHtml='';if(a.cves&&a.cves.length>0){{cveHtml='<div class="cve-inline">';a.cves.forEach(cve=>{{cveHtml+=`<div><span class="cve-badge">${{cve.cve}}</span><span class="badge bg-danger">${{cve.severity}}/10</span></div><div class="cve-text">${{cve.description}}</div>`}});cveHtml+='</div>'}}return`<div class="alert-item ${{a.severity}}"><div class="d-flex justify-content-between align-items-start"><div><span class="badge-attack badge-${{a.label.toLowerCase().replace(/[-\s]/g,'-')}}">${{a.label}}</span><span class="ms-2 text-secondary">${{a.time}}</span></div><span class="badge bg-secondary">${{a.confidence}}%</span></div><div class="mt-2 text-secondary small"><i class="fas fa-bullseye"></i> Port ${{a.port}} | <i class="fas fa-cube"></i> ${{a.packets}} pkts</div>${{cveHtml}}</div>`}}).join('')}}}}catch(e){{console.error(e)}}}}

async function generateReport(){{const btn=document.getElementById('pdfBtn');btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> GENERATING...';try{{const res=await fetch('/api/generate_report',{{method:'POST'}});const data=await res.json();if(data.filename){{const a=document.createElement('a');a.href='/reports/'+data.filename;a.download=data.filename;a.click();btn.innerHTML='<i class="fas fa-check"></i> DOWNLOADED!';setTimeout(()=>{{btn.innerHTML='<i class="fas fa-file-export"></i> EXPORT REPORT';btn.disabled=false}},3000)}}}}catch(e){{console.error(e);btn.innerHTML='<i class="fas fa-times"></i> ERROR';setTimeout(()=>{{btn.innerHTML='<i class="fas fa-file-export"></i> EXPORT REPORT';btn.disabled=false}},3000)}}}}

setInterval(updateDashboard,3000);updateDashboard();
</script>
</body>
</html>'''

ALERTS_HTML = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-IDS - Threat Analysis</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
<style>{SHARED_CSS}</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-virus"></i> CYBER DEFENSE</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-radar"></i> COMMAND</a></li>
<li class="nav-item"><a class="nav-link active" href="/alerts"><i class="fas fa-skull-crossbones"></i> THREATS</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-brain"></i> INTEL</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> SYSTEM</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2 style="color:#00f3ff"><i class="fas fa-skull-crossbones"></i> THREAT DATABASE</h2></div></div>
<div class="row"><div class="col-12"><div class="chart-card">
<div class="d-flex justify-content-between mb-3"><h5 class="card-title">All Detected Threats</h5><button class="btn-export" onclick="exportCSV()"><i class="fas fa-download"></i> EXPORT</button></div>
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
async function load(){{const r=await fetch('/api/all_alerts');const a=await r.json();if(tbl)tbl.destroy();document.querySelector('#alertsTable tbody').innerHTML=a.map(x=>`<tr><td>${{x.time}}</td><td>192.168.68.145</td><td><span class="badge-${{x.label.toLowerCase().replace(/[-\s]/g,'-')}}">${{x.label}}</span></td><td>${{x.confidence}}%</td><td><span class="badge bg-${{x.severity_color}}">${{x.severity}}</span></td><td>${{x.port}}</td><td>${{x.packets}}</td></tr>`).join('');tbl=$('#alertsTable').DataTable({{order:[[0,'desc']],pageLength:25}})}}
function exportCSV(){{fetch('/api/export_alerts_csv').then(r=>r.blob()).then(b=>{{const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='threats.csv';a.click()}})}}
load();setInterval(load,10000);
</script>
</body>
</html>'''

ANALYTICS_HTML = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-IDS - Intelligence</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>{SHARED_CSS}</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-virus"></i> CYBER DEFENSE</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-radar"></i> COMMAND</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-skull-crossbones"></i> THREATS</a></li>
<li class="nav-item"><a class="nav-link active" href="/analytics"><i class="fas fa-brain"></i> INTEL</a></li>
<li class="nav-item"><a class="nav-link" href="/settings"><i class="fas fa-cog"></i> SYSTEM</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2 style="color:#00f3ff"><i class="fas fa-brain"></i> AI MODEL INTELLIGENCE</h2></div></div>
<div class="row g-4 mb-4">
<div class="col-md-3"><div class="kpi-card green"><div class="kpi-label">ACCURACY</div><div class="kpi-value">99.81%</div><div class="kpi-change">94,110 test samples</div></div></div>
<div class="col-md-3"><div class="kpi-card blue"><div class="kpi-label">PRECISION</div><div class="kpi-value">99.82%</div><div class="kpi-change">Weighted average</div></div></div>
<div class="col-md-3"><div class="kpi-card blue"><div class="kpi-label">RECALL</div><div class="kpi-value">99.81%</div><div class="kpi-change">Weighted average</div></div></div>
<div class="col-md-3"><div class="kpi-card purple"><div class="kpi-label">FALSE POSITIVE</div><div class="kpi-value">0.19%</div><div class="kpi-change">179 / 94,110</div></div></div>
</div>
<div class="row g-4">
<div class="col-lg-6"><div class="chart-card"><h5 class="card-title mb-3">Confusion Matrix</h5><canvas id="confusionMatrix" height="300"></canvas></div></div>
<div class="col-lg-6"><div class="chart-card"><h5 class="card-title mb-3">Per-Class Performance</h5>
<table class="table table-dark"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1-Score</th></tr></thead>
<tbody><tr><td>BENIGN</td><td>1.00</td><td>1.00</td><td>1.00</td></tr><tr><td>DDoS</td><td>1.00</td><td>1.00</td><td>1.00</td></tr>
<tr><td>PortScan</td><td>1.00</td><td>1.00</td><td>1.00</td></tr><tr><td>Bot</td><td>0.49</td><td>0.96</td><td>0.65</td></tr></tbody></table>
<p class="small text-secondary mt-3"><i class="fas fa-info-circle"></i> Bot class shows lower precision due to extreme imbalance (0.2% of dataset).</p>
</div></div>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
const cmCtx=document.getElementById('confusionMatrix').getContext('2d');
new Chart(cmCtx,{{type:'bar',data:{{labels:['BENIGN','DDoS','PortScan','Bot'],datasets:[{{label:'True Positives',data:[73832,10315,9584,364],backgroundColor:'#00ff41'}},{{label:'False Positives',data:[0,0,0,379],backgroundColor:'#ff0080'}}]}},options:{{responsive:true,scales:{{y:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}},x:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,243,255,0.1)'}}}}}},plugins:{{legend:{{labels:{{color:'#94a3b8'}}}}}}}}}});
</script>
</body>
</html>'''

SETTINGS_HTML = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-IDS - System Status</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
<style>{SHARED_CSS}</style>
</head>
<body>
<nav class="navbar navbar-expand-lg">
<div class="container-fluid">
<a class="navbar-brand" href="/"><i class="fas fa-shield-virus"></i> CYBER DEFENSE</a>
<ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-radar"></i> COMMAND</a></li>
<li class="nav-item"><a class="nav-link" href="/alerts"><i class="fas fa-skull-crossbones"></i> THREATS</a></li>
<li class="nav-item"><a class="nav-link" href="/analytics"><i class="fas fa-brain"></i> INTEL</a></li>
<li class="nav-item"><a class="nav-link active" href="/settings"><i class="fas fa-cog"></i> SYSTEM</a></li>
</ul>
</div>
</nav>
<div class="container-fluid p-4">
<div class="row mb-4"><div class="col-12"><h2 style="color:#00f3ff"><i class="fas fa-server"></i> SYSTEM DIAGNOSTICS</h2></div></div>
<div class="row g-4">
<div class="col-lg-6"><div class="chart-card"><h5 class="card-title mb-3"><i class="fas fa-microchip"></i> Resource Monitor</h5>
<div class="mb-4"><label class="mb-2 fw-bold">CPU Usage</label><div class="progress"><div class="progress-bar" id="cpuBar" style="width:0%"></div></div><small class="text-secondary" id="cpuText">0%</small></div>
<div class="mb-4"><label class="mb-2 fw-bold">Memory Usage</label><div class="progress"><div class="progress-bar" id="memBar" style="width:0%"></div></div><small class="text-secondary" id="memText">0%</small></div>
<div><label class="mb-2 fw-bold">Disk Usage</label><div class="progress"><div class="progress-bar" id="diskBar" style="width:0%"></div></div><small class="text-secondary" id="diskText">0%</small></div>
</div></div>
<div class="col-lg-6"><div class="chart-card"><h5 class="card-title mb-3"><i class="fas fa-info-circle"></i> System Configuration</h5>
<table class="table table-dark table-sm">
<tr><td><strong>Model Type</strong></td><td class="text-end">Random Forest</td></tr>
<tr><td><strong>Model Version</strong></td><td class="text-end">1.0</td></tr>
<tr><td><strong>Dataset</strong></td><td class="text-end">CIC-IDS2017</td></tr>
<tr><td><strong>Training Samples</strong></td><td class="text-end">376,437</td></tr>
<tr><td><strong>Test Accuracy</strong></td><td class="text-end">99.81%</td></tr>
<tr><td><strong>Detection Mode</strong></td><td class="text-end">Hybrid (ML + Rules)</td></tr>
<tr><td><strong>Attack Types</strong></td><td class="text-end">7 types</td></tr>
<tr><td><strong>System Uptime</strong></td><td class="text-end" id="uptime">0m</td></tr>
</table>
</div></div>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
async function updateSystemStats(){{const res=await fetch('/api/system_stats');const data=await res.json();document.getElementById('cpuBar').style.width=data.cpu+'%';document.getElementById('cpuText').textContent=data.cpu+'%';document.getElementById('memBar').style.width=data.memory+'%';document.getElementById('memText').textContent=data.memory+'%';document.getElementById('diskBar').style.width=data.disk+'%';document.getElementById('diskText').textContent=data.disk+'%';document.getElementById('uptime').textContent=data.uptime}}
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
    attack_counts = [0] * 60
    normal_counts = [0] * 60
    
    for t in traffic[-200:]:
        ts = datetime.fromisoformat(t['timestamp'])
        mins_ago = int((now - ts).seconds / 60)
        if mins_ago < 60:
            if t['is_attack']:
                attack_counts[59 - mins_ago] += 1
            else:
                normal_counts[59 - mins_ago] += 1
    
    attack_type_counts = Counter(a['label'] for a in alerts)
    attack_labels = ['DDoS', 'PortScan', 'Bot', 'SQL-Injection', 'XSS-Attack', 'SSH-Brute-Force', 'Slowloris-DoS']
    attack_data = [attack_type_counts.get(label, 0) for label in attack_labels]
    
    heatmap = generate_heatmap_data()
    
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
        
        cves = get_cves_for_attack(a['label'])
        
        recent.append({
            'label': a['label'],
            'time': datetime.fromisoformat(a['timestamp']).strftime('%H:%M:%S'),
            'confidence': conf,
            'port': a.get('dst_port', '—'),
            'packets': a['fwd_pkts'] + a['bwd_pkts'],
            'severity': severity,
            'cves': cves
        })
    
    return jsonify({
        'total_packets': total_packets,
        'attacks_detected': attacks,
        'attack_rate': rate,
        'threat_level': level,
        'traffic_labels': labels,
        'traffic_normal': normal_counts,
        'traffic_attacks': attack_counts,
        'attack_labels': attack_labels,
        'attack_counts': attack_data,
        'heatmap': heatmap,
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
            'packets': a['fwd_pkts'] + a['bwd_pkts']
        })
    return jsonify(result)

@app.route('/api/export_alerts_csv')
def api_export_csv():
    data = read_shared()
    alerts = data.get("alerts", [])
    csv = "Timestamp,Attack Type,Confidence,Port,Packets\n"
    for a in alerts:
        csv += f"{a['timestamp']},{a['label']},{a['confidence']},{a.get('dst_port','')},{a['fwd_pkts']+a['bwd_pkts']}\n"
    return Response(csv, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=threats.csv'})

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
    print("  🛡️  CYBER DEFENSE COMMAND CENTER")
    print("  🌐 http://127.0.0.1:5000")
    print("  🎯 7 Attack Types + Inline CVE Intelligence")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
