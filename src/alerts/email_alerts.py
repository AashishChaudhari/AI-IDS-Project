#!/usr/bin/env python3
"""
AI-IDS Professional Email Alert System
Sends detailed, professional email alerts ONLY for newly detected attacks
"""
import smtplib, json, time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
CONFIG_FILE = BASE_DIR / 'config' / 'email_config.json'

# CVE Database for each attack type
CVE_DATABASE = {
    'DDoS': [
        {'cve': 'CVE-2024-3400', 'severity': 10.0, 'title': 'PAN-OS Command Injection'},
        {'cve': 'CVE-2023-46604', 'severity': 10.0, 'title': 'Apache ActiveMQ RCE'}
    ],
    'PortScan': [
        {'cve': 'CVE-2024-21887', 'severity': 9.1, 'title': 'Ivanti Connect Pre-Auth'},
        {'cve': 'CVE-2023-22515', 'severity': 10.0, 'title': 'Confluence Privilege Escalation'}
    ],
    'Bot': [
        {'cve': 'CVE-2024-23897', 'severity': 9.8, 'title': 'Jenkins File Read Exploit'},
        {'cve': 'CVE-2023-27997', 'severity': 9.2, 'title': 'FortiOS Heap Overflow'}
    ],
    'SQL-Injection': [
        {'cve': 'CVE-2024-27348', 'severity': 9.8, 'title': 'Apache HugeGraph SQLi RCE'},
        {'cve': 'CVE-2023-34362', 'severity': 9.8, 'title': 'MOVEit Transfer SQLi Zero-Day'}
    ],
    'XSS-Attack': [
        {'cve': 'CVE-2024-21762', 'severity': 9.6, 'title': 'FortiOS SSL-VPN XSS to RCE'},
        {'cve': 'CVE-2023-51467', 'severity': 9.8, 'title': 'Apache OFBiz XSS RCE'}
    ],
    'SSH-Brute-Force': [
        {'cve': 'CVE-2024-6387', 'severity': 8.1, 'title': 'OpenSSH regreSSHion RCE'},
        {'cve': 'CVE-2023-48795', 'severity': 5.9, 'title': 'Terrapin SSH Attack'}
    ],
    'Slowloris-DoS': [
        {'cve': 'CVE-2023-44487', 'severity': 7.5, 'title': 'HTTP/2 Rapid Reset DDoS'},
        {'cve': 'CVE-2022-41742', 'severity': 7.5, 'title': 'NGINX Slow HTTP DoS'}
    ]
}

# Mitigation recommendations for each attack type
MITIGATIONS = {
    'DDoS': [
        'Enable rate limiting on firewall and load balancer',
        'Activate DDoS protection service (Cloudflare, AWS Shield)',
        'Block attacking IP ranges at network perimeter',
        'Scale infrastructure horizontally if possible',
        'Contact ISP for upstream filtering'
    ],
    'PortScan': [
        'Block scanning source IP at firewall',
        'Close unnecessary open ports immediately',
        'Enable SYN flood protection',
        'Review and update firewall rules',
        'Implement port knocking for sensitive services'
    ],
    'Bot': [
        'Block botnet C2 communication at DNS/firewall level',
        'Scan infected systems with anti-malware tools',
        'Isolate compromised hosts from network',
        'Review recent process executions and network connections',
        'Update all systems and patch known vulnerabilities'
    ],
    'SQL-Injection': [
        'Block attacking IP address immediately',
        'Review and patch vulnerable application code',
        'Enable Web Application Firewall (WAF)',
        'Use parameterized queries/prepared statements',
        'Implement input validation and sanitization',
        'Review database logs for unauthorized access'
    ],
    'XSS-Attack': [
        'Block attacking IP address',
        'Sanitize all user inputs on server-side',
        'Enable Content Security Policy (CSP) headers',
        'Use HTTPOnly and Secure flags on cookies',
        'Implement output encoding for all dynamic content'
    ],
    'SSH-Brute-Force': [
        'Block attacking IP with fail2ban or firewall',
        'Disable password authentication (use SSH keys only)',
        'Change SSH port from default 22',
        'Implement rate limiting on SSH connections',
        'Review /var/log/auth.log for successful breaches'
    ],
    'Slowloris-DoS': [
        'Enable connection timeouts on web server',
        'Limit concurrent connections per IP',
        'Use reverse proxy with DoS protection',
        'Increase server timeout values carefully',
        'Deploy CDN with DDoS mitigation'
    ]
}

def get_threat_level(confidence):
    """Determine threat level based on confidence"""
    if confidence >= 95:
        return "CRITICAL", "#dc2626"
    elif confidence >= 85:
        return "HIGH", "#ef4444"
    elif confidence >= 75:
        return "MEDIUM", "#f59e0b"
    else:
        return "LOW", "#22c55e"

def get_attack_icon(label):
    """Get emoji icon for attack type"""
    icons = {
        'DDoS': '🌊',
        'PortScan': '🔍',
        'Bot': '🤖',
        'SQL-Injection': '💉',
        'XSS-Attack': '🎭',
        'SSH-Brute-Force': '🔐',
        'Slowloris-DoS': '🐌'
    }
    return icons.get(label, '⚠️')

def build_professional_email(attack):
    """Build professional HTML email for the attack"""
    label = attack['label']
    conf = attack['confidence']
    threat_level, color = get_threat_level(conf)
    icon = get_attack_icon(label)
    timestamp = datetime.fromisoformat(attack['timestamp'])
    port = attack.get('dst_port', 'N/A')
    packets = attack['fwd_pkts'] + attack['bwd_pkts']
    
    # Get CVEs and mitigations
    cves = CVE_DATABASE.get(label, [])[:2]
    mitigations = MITIGATIONS.get(label, ['Review system logs', 'Monitor for further activity'])
    
    # Build CVE section
    cve_html = ""
    for cve in cves:
        sev_color = "#dc2626" if cve['severity'] >= 9 else "#f59e0b"
        cve_html += f"""
        <div style="background:#f9fafb;padding:12px;margin:8px 0;border-radius:6px;border-left:3px solid {sev_color}">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-family:Courier,monospace;font-weight:700;color:{sev_color}">{cve['cve']}</span>
                <span style="background:{sev_color};color:white;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700">{cve['severity']}/10</span>
            </div>
            <div style="color:#6b7280;font-size:13px;margin-top:4px">{cve['title']}</div>
        </div>
        """
    
    # Build mitigation section
    mitigation_html = ""
    for i, tip in enumerate(mitigations[:5], 1):
        mitigation_html += f"""
        <div style="padding:10px 0;border-bottom:1px solid #e5e7eb">
            <div style="display:flex;align-items:start">
                <span style="background:#3b82f6;color:white;width:24px;height:24px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;margin-right:12px">{i}</span>
                <span style="color:#374151;line-height:24px">{tip}</span>
            </div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f3f4f6">
        <div style="max-width:600px;margin:20px auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 6px rgba(0,0,0,0.1)">
            
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#1e293b 0%,#334155 100%);padding:30px;text-align:center">
                <div style="font-size:24px;font-weight:900;color:white;letter-spacing:1px;margin-bottom:8px">
                    🛡️ AI-IDS PROFESSIONAL
                </div>
                <div style="color:#94a3b8;font-size:13px;letter-spacing:2px">
                    INTRUSION DETECTION SYSTEM — LIVE ALERT
                </div>
            </div>
            
            <!-- Threat Banner -->
            <div style="background:{color};padding:20px;text-align:center">
                <div style="font-size:48px;margin-bottom:8px">{icon}</div>
                <div style="color:white;font-size:22px;font-weight:700;letter-spacing:0.5px">
                    {threat_level} THREAT DETECTED
                </div>
                <div style="color:rgba(255,255,255,0.9);font-size:18px;font-weight:600;margin-top:8px">
                    {label}
                </div>
            </div>
            
            <!-- Attack Details -->
            <div style="padding:30px">
                <h2 style="color:#1f2937;font-size:18px;font-weight:700;margin:0 0 20px 0;border-bottom:2px solid #e5e7eb;padding-bottom:10px">
                    📊 Attack Details
                </h2>
                
                <table style="width:100%;border-collapse:collapse">
                    <tr>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;font-weight:600">Attack Type</td>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#1f2937;font-weight:700;text-align:right">{label}</td>
                    </tr>
                    <tr>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;font-weight:600">Threat Level</td>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;text-align:right">
                            <span style="background:{color};color:white;padding:4px 12px;border-radius:4px;font-weight:700;font-size:12px">{threat_level}</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;font-weight:600">Confidence</td>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#1f2937;font-weight:700;text-align:right">{conf}%</td>
                    </tr>
                    <tr>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;font-weight:600">Timestamp</td>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#1f2937;text-align:right">{timestamp.strftime('%B %d, %Y at %H:%M:%S')}</td>
                    </tr>
                    <tr>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;font-weight:600">Target Port</td>
                        <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#1f2937;font-weight:700;text-align:right">{port}</td>
                    </tr>
                    <tr>
                        <td style="padding:12px 0;color:#6b7280;font-weight:600">Packets Detected</td>
                        <td style="padding:12px 0;color:#1f2937;font-weight:700;text-align:right">{packets:,}</td>
                    </tr>
                </table>
            </div>
            
            <!-- CVE Vulnerabilities -->
            {f'''
            <div style="padding:0 30px 30px 30px">
                <h2 style="color:#1f2937;font-size:18px;font-weight:700;margin:0 0 15px 0;border-bottom:2px solid #e5e7eb;padding-bottom:10px">
                    🐛 Related CVE Vulnerabilities
                </h2>
                {cve_html}
            </div>
            ''' if cves else ''}
            
            <!-- Recommended Actions -->
            <div style="padding:0 30px 30px 30px">
                <h2 style="color:#1f2937;font-size:18px;font-weight:700;margin:0 0 15px 0;border-bottom:2px solid #e5e7eb;padding-bottom:10px">
                    ✅ Recommended Actions
                </h2>
                {mitigation_html}
            </div>
            
            <!-- Dashboard Link -->
            <div style="padding:0 30px 30px 30px;text-align:center">
                <a href="http://localhost:5000" style="display:inline-block;background:#3b82f6;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;letter-spacing:0.5px;box-shadow:0 2px 4px rgba(59,130,246,0.3)">
                    📊 VIEW FULL DETAILS ON DASHBOARD
                </a>
            </div>
            
            <!-- Footer -->
            <div style="background:#f9fafb;padding:20px 30px;border-top:1px solid #e5e7eb;text-align:center">
                <div style="color:#6b7280;font-size:14px;margin-bottom:8px">
                    <span style="font-weight:700;color:#1f2937">AI-IDS Professional</span> | Developed by Aashish Chaudhari
                </div>
                <div style="color:#9ca3af;font-size:12px">
                    Alert generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div style="color:#9ca3af;font-size:11px;margin-top:8px">
                    This is an automated security alert. Do not reply to this email.
                </div>
            </div>
            
        </div>
    </body>
    </html>
    """
    return html

class EmailAlerter:
    def __init__(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                self.config = json.load(f)
            self.enabled = True
        except:
            print("⚠️  Email config not found. Run setup at end of script.")
            self.enabled = False
        self.last_sent = {}
    
    def send_alert(self, attack):
        """Send one professional email per attack"""
        if not self.enabled:
            return False
        
        label = attack['label']
        now = time.time()
        cooldown = self.config.get('alert_cooldown', 30)
        
        # Cooldown check to prevent spam
        if label in self.last_sent and (now - self.last_sent[label]) < cooldown:
            return False
        
        try:
            conf = attack['confidence']
            threat_level, _ = get_threat_level(conf)
            
            msg = MIMEMultipart('alternative')
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            msg['Subject'] = f"[AI-IDS] {threat_level} - {label} Attack Detected ({conf}%)"
            
            html = build_professional_email(attack)
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], self.config['sender_password'])
                server.send_message(msg)
            
            self.last_sent[label] = now
            ts = datetime.fromisoformat(attack['timestamp']).strftime('%H:%M:%S')
            print(f"✅ [{threat_level}] Email sent: {label} @ {ts} → {self.config['recipient_email']}")
            return True
            
        except Exception as e:
            print(f"❌ Email failed: {str(e)[:80]}")
            return False

class AlertMonitor:
    def __init__(self):
        self.emailer = EmailAlerter()
        self.shared_file = BASE_DIR / 'data' / 'live_results.json'
        self.running = True
        self.last_alert_count = 0
        
        # Initialize: count existing alerts so we don't email about them
        try:
            with open(self.shared_file, 'r') as f:
                data = json.load(f)
            self.last_alert_count = len(data.get('alerts', []))
            print(f"📋 Found {self.last_alert_count} existing alerts (will NOT email about these)")
        except:
            self.last_alert_count = 0
    
    def start(self):
        if not self.emailer.enabled:
            print("\n❌ Email not configured. Exiting.")
            print("📝 Configure email by editing: config/email_config.json")
            return
        
        print("\n" + "="*70)
        print("  🛡️  AI-IDS PROFESSIONAL EMAIL ALERT MONITOR")
        print("="*70)
        print(f"  📧 Recipient   : {self.emailer.config['recipient_email']}")
        print(f"  ⏱️  Cooldown   : {self.emailer.config.get('alert_cooldown', 30)}s per attack type")
        print(f"  📂 Monitoring  : {self.shared_file}")
        print(f"  🎯 Mode        : Email ONLY for NEW attacks")
        print("="*70 + "\n")
        print("⏳ Waiting for new attacks to be detected...\n")
        
        while self.running:
            try:
                with open(self.shared_file, 'r') as f:
                    data = json.load(f)
                
                alerts = data.get('alerts', [])
                current_count = len(alerts)
                
                # Only process NEW alerts
                if current_count > self.last_alert_count:
                    new_alerts = alerts[self.last_alert_count:]
                    for alert in new_alerts:
                        self.emailer.send_alert(alert)
                    self.last_alert_count = current_count
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                self.running = False
                print("\n✅ Email monitor stopped gracefully.")
            except FileNotFoundError:
                time.sleep(5)
            except Exception as e:
                print(f"⚠️  Error: {str(e)[:50]}")
                time.sleep(5)

if __name__ == "__main__":
    monitor = AlertMonitor()
    monitor.start()
