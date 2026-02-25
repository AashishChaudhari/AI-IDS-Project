# AI-IDS Attack Simulation Guide

## 🎯 Attack Scenarios

### 1. SSH Brute Force Attack
**From Attacker VM (Kali):**
```bash
for i in {1..15}; do 
  ssh -o ConnectTimeout=1 root@192.168.68.152 2>/dev/null & 
done
```
**Expected Detection:** SSH-Brute-Force (90-99% confidence)

### 2. Privilege Escalation
**Setup on IDS VM:**
```bash
sudo useradd -m testuser
echo "testuser:testpass123" | sudo chpasswd
```

**From Attacker VM:**
```bash
sshpass -p "testpass123" ssh testuser@192.168.68.152 << 'EOFS'
sudo whoami
sudo -l
sudo cat /etc/shadow
EOFS
```
**Expected Detection:** Privilege-Escalation (88-95% confidence)

### 3. SQL Injection Attack
```bash
curl "http://192.168.68.152/?id=1' OR '1'='1"
curl "http://192.168.68.152/login?user=admin'--"
```
**Expected Detection:** SQL-Injection (92% confidence)

### 4. Port Scan
```bash
nmap -p 1-100 192.168.68.152
```
**Expected Detection:** PortScan (85-99% confidence)

### 5. XSS Attack
```bash
curl "http://192.168.68.152/?q=<script>alert(1)</script>"
```
**Expected Detection:** XSS-Attack (90% confidence)

## 📊 Detection Thresholds
| Attack | Threshold | Confidence |
|--------|-----------|------------|
| SSH Brute Force | 10+ attempts/10s | 90-99% |
| Privilege Escalation | 3+ sudo/30s | 88-95% |
| SQL Injection | Pattern match | 92% |
| Port Scan | 10+ ports | 85-99% |

## 🔒 Safety Notes
- Only test on your own VMs
- Reset after testing
- Educational purposes only
