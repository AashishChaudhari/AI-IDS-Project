#!/usr/bin/env python3
"""
AI-IDS Email Alert System
Triggers on every attack - includes attack type, confidence, timestamp, port, threat level
"""
import smtplib
import json
import time
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
CONFIG_FILE = BASE_DIR / 'config' / 'email_config.json'

DEFAULT_CONFIG = {
    "sender_email": "your_gmail@gmail.com",
    "sender_password": "your_app_password_here",
    "receiver_email": "your_email@gmail.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "cooldown_seconds": 30,
    "enabled": True
}


def get_threat_level(confidence):
    if confidence >= 95:
        return "CRITICAL", "#dc2626", "#fef2f2"
    elif confidence >= 85:
        return "HIGH", "#ef4444", "#fff5f5"
    elif confidence >= 75:
        return "MEDIUM", "#f59e0b", "#fffbeb"
    else:
        return "LOW", "#22c55e", "#f0fdf4"


def get_mitigation(label):
    tips = {
        "DDoS": [
            "Block source IP at firewall immediately",
            "Enable rate limiting on affected interface",
            "Contact ISP if attack is large-scale"
        ],
        "PortScan": [
            "Block scanning source IP",
            "Review and close unnecessary open ports",
            "Enable port scan detection on firewall"
        ],
        "Bot": [
            "Isolate potentially compromised hosts",
            "Run malware scan on internal systems",
            "Review outbound connections for C&C traffic"
        ]
    }
    return tips.get(label, ["Review dashboard for more details"])


def build_email_html(attack):
    label = attack['label']
    confidence = attack['confidence']
    port = attack.get('dst_port', '—')
    timestamp = datetime.fromisoformat(attack['timestamp']).strftime('%B %d, %Y at %H:%M:%S')
    packets = attack['fwd_pkts'] + attack.get('bwd_pkts', 0)

    threat_level, sev_color, sev_bg = get_threat_level(confidence)
    mitigation = get_mitigation(label)

    type_colors = {
        'DDoS': '#ef4444',
        'PortScan': '#f59e0b',
        'Bot': '#a855f7'
    }
    type_color = type_colors.get(label, '#64748b')

    mitigation_items = ''.join(f'<li style="margin-bottom:6px;">{tip}</li>' for tip in mitigation)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif;">

<!-- Top Header -->
<div style="background:#0f172a;padding:20px 32px;text-align:center;">
  <h1 style="color:#3b82f6;margin:0;font-size:22px;">🛡️ AI-IDS Professional</h1>
  <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;">Intrusion Detection System — Live Alert</p>
</div>

<!-- Severity Banner -->
<div style="background:{sev_color};padding:14px 32px;text-align:center;">
  <h2 style="color:white;margin:0;font-size:18px;letter-spacing:1px;">
    ⚠️ {threat_level} THREAT — {label} ATTACK DETECTED
  </h2>
</div>

<!-- Card -->
<div style="max-width:580px;margin:24px auto;background:white;border-radius:12px;
            overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.1);">

  <!-- Attack Info -->
  <div style="padding:24px 32px;background:{sev_bg};border-bottom:3px solid {sev_color};">
    <h3 style="margin:0 0 16px;color:#1e293b;font-size:16px;">📋 Attack Details</h3>
    <table style="width:100%;border-collapse:collapse;">
      <tr>
        <td style="padding:10px 0;color:#64748b;width:45%;font-size:14px;">Attack Type</td>
        <td style="padding:10px 0;font-weight:bold;color:{type_color};font-size:14px;">{label}</td>
      </tr>
      <tr style="border-top:1px solid #e2e8f0;">
        <td style="padding:10px 0;color:#64748b;font-size:14px;">Threat Level</td>
        <td style="padding:10px 0;font-size:14px;">
          <span style="background:{sev_color};color:white;padding:3px 10px;
                       border-radius:20px;font-size:12px;font-weight:bold;">{threat_level}</span>
        </td>
      </tr>
      <tr style="border-top:1px solid #e2e8f0;">
        <td style="padding:10px 0;color:#64748b;font-size:14px;">Confidence</td>
        <td style="padding:10px 0;font-weight:bold;color:#1e293b;font-size:14px;">{confidence}%</td>
      </tr>
      <tr style="border-top:1px solid #e2e8f0;">
        <td style="padding:10px 0;color:#64748b;font-size:14px;">Timestamp</td>
        <td style="padding:10px 0;color:#1e293b;font-size:14px;">{timestamp}</td>
      </tr>
      <tr style="border-top:1px solid #e2e8f0;">
        <td style="padding:10px 0;color:#64748b;font-size:14px;">Target Port</td>
        <td style="padding:10px 0;font-weight:bold;color:#1e293b;font-size:14px;">{port}</td>
      </tr>
      <tr style="border-top:1px solid #e2e8f0;">
        <td style="padding:10px 0;color:#64748b;font-size:14px;">Packets Detected</td>
        <td style="padding:10px 0;color:#1e293b;font-size:14px;">{packets:,}</td>
      </tr>
    </table>
  </div>

  <!-- Mitigation -->
  <div style="padding:24px 32px;border-bottom:1px solid #e2e8f0;">
    <h3 style="margin:0 0 12px;color:#1e293b;font-size:16px;">⚡ Recommended Actions</h3>
    <ul style="color:#475569;padding-left:20px;line-height:1.8;font-size:14px;margin:0;">
      {mitigation_items}
      <li>View full details on the <a href="http://192.168.68.152:5000" style="color:#3b82f6;">IDS Dashboard</a></li>
    </ul>
  </div>

  <!-- Footer -->
  <div style="padding:16px 32px;background:#f8fafc;text-align:center;">
    <p style="color:#94a3b8;font-size:12px;margin:0;">
      AI-IDS Professional &nbsp;|&nbsp; Developed by Aashish Chaudhari<br>
      Alert generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>
  </div>
</div>
</body>
</html>"""


class EmailAlerter:
    def __init__(self):
        self.config = self._load_config()
        self.last_sent = {}
        self._lock = threading.Lock()

    def _load_config(self):
        CONFIG_FILE.parent.mkdir(exist_ok=True)
        if not CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"⚠️  Config created: {CONFIG_FILE}")
            print("    Edit it with your Gmail credentials!")
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)

    def is_configured(self):
        return (
            'your_gmail' not in self.config['sender_email'] and
            'your_app_password' not in self.config['sender_password'] and
            self.config.get('enabled', True)
        )

    def send_alert(self, attack):
        with self._lock:
            if not self.is_configured():
                print("⚠️  Email not configured. Edit config/email_config.json")
                return False

            label = attack['label']
            now = time.time()
            cooldown = self.config.get('cooldown_seconds', 30)

            if label in self.last_sent:
                elapsed = now - self.last_sent[label]
                if elapsed < cooldown:
                    remaining = int(cooldown - elapsed)
                    print(f"⏳ Cooldown: {label} — next email in {remaining}s")
                    return False

            try:
                msg = MIMEMultipart('alternative')
                confidence = attack['confidence']
                threat_level, _, _ = get_threat_level(confidence)

                msg['Subject'] = (
                    f"🚨 [{threat_level}] {label} Attack Detected — "
                    f"{confidence}% Confidence | AI-IDS"
                )
                msg['From'] = self.config['sender_email']
                msg['To'] = self.config['receiver_email']

                html = build_email_html(attack)
                msg.attach(MIMEText(html, 'html'))

                with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                    server.starttls()
                    server.login(self.config['sender_email'], self.config['sender_password'])
                    server.sendmail(
                        self.config['sender_email'],
                        self.config['receiver_email'],
                        msg.as_string()
                    )

                self.last_sent[label] = now
                ts = datetime.fromisoformat(attack['timestamp']).strftime('%H:%M:%S')
                print(f"✅ Email sent: [{threat_level}] {label} @ {ts} → {self.config['receiver_email']}")
                return True

            except Exception as e:
                print(f"❌ Email failed: {e}")
                return False


class AlertMonitor:
    def __init__(self):
        self.emailer = EmailAlerter()
        self.shared_file = BASE_DIR / 'data' / 'live_results.json'
        self.last_count = 0
        self.running = True

    def start(self):
        print("\n" + "="*55)
        print("  AI-IDS EMAIL ALERT MONITOR")
        print("="*55)
        print(f"  Recipient : {self.emailer.config['receiver_email']}")
        print(f"  Trigger   : Every attack detected")
        print(f"  Cooldown  : {self.emailer.config.get('cooldown_seconds', 30)}s per attack type")
        print(f"  Watching  : {self.shared_file}")
        print("="*55 + "\n")

        while self.running:
            try:
                with open(self.shared_file, 'r') as f:
                    data = json.load(f)

                alerts = data.get('alerts', [])
                if len(alerts) > self.last_count:
                    new_alerts = alerts[self.last_count:]
                    for attack in new_alerts:
                        self.emailer.send_alert(attack)
                    self.last_count = len(alerts)

            except FileNotFoundError:
                print("⏳ Waiting for capture to start...")
            except Exception as e:
                print(f"⚠️  Monitor error: {e}")

            time.sleep(3)

    def stop(self):
        self.running = False
        print("\n✅ Email monitor stopped.")


if __name__ == '__main__':
    monitor = AlertMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
