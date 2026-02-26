# 🛡️ AI-IDS Professional

**Advanced Intrusion Detection System with Machine Learning**

A real-time network intrusion detection system that combines machine learning with behavioral analysis to detect and respond to cyber threats with 99.8% accuracy.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Accuracy](https://img.shields.io/badge/accuracy-99.8%25-green.svg)

---

## 🎯 Features

### Detection Capabilities
- **7 Attack Types Detected**:
  - DDoS (Distributed Denial of Service)
  - Port Scanning
  - Botnet Activity
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - SSH Brute Force
  - Slowloris DoS

### Hybrid Detection System
- **Machine Learning**: Random Forest classifier trained on CIC-IDS2017 dataset
- **Behavioral Rules**: Pattern-based detection for application-layer attacks
- **Real-time Analysis**: Live packet capture and instant threat detection

### Professional Dashboard
- **Neon-themed UI** with real-time updates
- **Attack Distribution** visualization
- **Attack Heatmap** (24x7 temporal analysis)
- **Inline CVE Intelligence** for each detected attack
- **Live threat feed** with severity indicators
- **System diagnostics** and resource monitoring

### Alert & Response
- **Email Alerts**: Professional HTML emails with CVE mappings and mitigation steps
- **SQLite Database**: Persistent storage of all detected threats
- **PDF Reports**: Comprehensive security reports with charts
- **Automated Response**: Configurable actions per attack type

---

## 📊 Performance Metrics

- **Overall Accuracy**: 99.81%
- **Precision**: 99.82%
- **Recall**: 99.81%
- **False Positive Rate**: 0.19%
- **Training Dataset**: CIC-IDS2017 (470,000+ samples)
- **Detection Speed**: Real-time (<100ms per packet)

---

## 🏗️ Architecture
```
AI-IDS-Project/
├── src/
│   ├── capture/          # Packet capture & detection
│   ├── dashboard/        # Web dashboard (Flask)
│   ├── alerts/           # Email alert system
│   ├── database/         # SQLite ORM models
│   ├── ml/              # ML model training
│   └── preprocessing/    # Data preprocessing
├── models/              # Trained ML models
├── data/
│   ├── processed/       # Preprocessed datasets
│   └── raw/            # Raw datasets
├── config/             # Configuration files
├── reports/            # Generated PDF reports
└── scripts/            # Utility scripts
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Root/sudo access (for packet capture)
- Network interface for monitoring

### Quick Start
```bash
# Clone repository
git clone https://github.com/yourusername/AI-IDS-Project.git
cd AI-IDS-Project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install scapy scikit-learn pandas numpy flask sqlalchemy reportlab matplotlib psutil colorama

# Initialize database
python -c "from src.database import init_database; init_database()"

# Train model (or use pre-trained)
python src/ml/train_fast.py
```

---

## 💻 Usage

### 1. Start the Dashboard
```bash
python src/dashboard/app_live.py
```
Access at: **http://localhost:5000**

### 2. Start Packet Capture
```bash
# Monitor specific interface
sudo venv/bin/python src/capture/packet_capture.py --iface eth0

# With BPF filter
sudo venv/bin/python src/capture/packet_capture.py --iface eth0 --filter "tcp port 80"
```

### 3. Email Alerts (Optional)
```bash
# Configure email (see Configuration section)
cp config/email_config.example.json config/email_config.json
nano config/email_config.json

# Start email monitor
python src/alerts/email_alerts.py
```

### 4. View Database
```bash
python scripts/view_database.py
```

---

## ⚙️ Configuration

### Email Alerts

Edit `config/email_config.json`:
```json
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "sender_email": "your_email@gmail.com",
  "sender_password": "your_gmail_app_password",
  "recipient_email": "recipient@gmail.com",
  "alert_cooldown": 30
}
```

**Gmail Setup**:
1. Enable 2-Factor Authentication
2. Generate App Password: Google Account → Security → App Passwords
3. Use app password (not your regular password)

---

## 🎨 Dashboard Features

### Main Dashboard (`/`)
- **Real-time KPIs**: Packets analyzed, threats detected, threat level
- **Live Charts**: Network activity stream, attack distribution
- **Attack Heatmap**: 24-hour temporal analysis
- **Threat Feed**: Recent attacks with inline CVE information

### Alerts Page (`/alerts`)
- Searchable alert database
- Export to CSV
- Detailed attack information

### Analytics Page (`/analytics`)
- Model performance metrics
- Confusion matrix
- Per-class accuracy

### System Page (`/settings`)
- Resource monitoring (CPU, Memory, Disk)
- System configuration
- Uptime tracking

---

## 🗄️ Database Schema

### Alerts Table
Stores all detected attacks with:
- Timestamp, attack type, confidence
- Source/destination IP and ports
- Packet statistics
- Detection method (ML/Rule/Hybrid)
- CVE associations
- Response actions

### Traffic Logs
Network statistics:
- Packet counts (total, benign, malicious)
- Protocol breakdown
- Bandwidth metrics

### System Events
- System status changes
- Errors and warnings
- Configuration updates

---

## 📧 Email Alerts

Professional HTML emails include:
- **Attack Details**: Type, confidence, timestamp, port
- **CVE Vulnerabilities**: Related CVEs with severity scores
- **Mitigation Steps**: Actionable recommendations
- **Dashboard Link**: Direct access to full details

Example:
```
🛡️ AI-IDS PROFESSIONAL
CRITICAL THREAT DETECTED - SQL Injection

Attack Details:
- Type: SQL-Injection
- Confidence: 98%
- Port: 80
- Timestamp: Feb 26, 2026 10:23:45

Related CVEs:
CVE-2024-27348 [9.8/10] - Apache HugeGraph SQLi RCE

Recommended Actions:
1. Block attacking IP immediately
2. Enable Web Application Firewall
3. Use parameterized queries
```

---

## 📈 Attack Detection Methods

### ML-Based Detection
- **DDoS**: Traffic volume analysis
- **PortScan**: Connection pattern recognition
- **Bot**: Behavioral fingerprinting

### Rule-Based Detection
- **SQL Injection**: Payload pattern matching (`UNION SELECT`, `DROP TABLE`)
- **XSS**: JavaScript injection detection (`<script>`, `onerror=`)
- **SSH Brute Force**: Failed login rate monitoring (10+ attempts/10s)
- **Slowloris DoS**: Slow HTTP connection tracking (20+ slow connections)

---

## 📊 Reports

Generate comprehensive PDF reports:
```bash
# Via Dashboard: Click "Export Report" button
# Or manually:
python -c "from src.dashboard.report_generator import IDSReportGenerator; import json; alerts=json.load(open('data/live_results.json'))['alerts']; IDSReportGenerator(alerts).generate_report()"
```

Reports include:
- Executive summary
- Attack distribution charts
- Timeline analysis
- Severity breakdown
- Detailed alert log

---

## 🛠️ Tech Stack

**Backend**:
- Python 3.8+
- Scapy (packet capture)
- scikit-learn (ML)
- Flask (web server)
- SQLAlchemy (ORM)

**Frontend**:
- HTML5, CSS3, JavaScript
- Chart.js (visualizations)
- Bootstrap 5 (UI)
- DataTables (alert tables)

**Data & ML**:
- NumPy, Pandas
- Random Forest Classifier
- StandardScaler, LabelEncoder

**Reporting**:
- ReportLab (PDF generation)
- Matplotlib (charts)

---

## 🧪 Testing

### Simulate Attacks
```bash
# Port Scan
nmap -p 1-100 localhost

# HTTP Flood (DDoS simulation)
ab -n 10000 -c 100 http://localhost/

# SSH Brute Force (multiple failed attempts)
# Use hydra or similar tools (ethical testing only!)
```

---

## 🔒 Security Considerations

- **Root Access**: Packet capture requires sudo/root privileges
- **Network Monitoring**: Ensure compliance with network policies
- **Data Privacy**: Captured packets may contain sensitive information
- **Email Security**: Use app passwords, never commit credentials
- **Database**: SQLite file permissions should be restricted

---

## 📝 Maintenance

### Database Management
```bash
# View statistics
python scripts/view_database.py

# Backup database
cp data/ids_database.db backups/ids_db_$(date +%Y%m%d).db

# Clear old alerts (>30 days)
sqlite3 data/ids_database.db "DELETE FROM alerts WHERE timestamp < datetime('now', '-30 days');"
```

### Model Retraining
```bash
# With new data
python src/ml/train_fast.py

# Full preprocessing
python src/preprocessing/cicids2017_preprocessor.py
python src/ml/train_fast.py
```

---

## 🐛 Troubleshooting

### Issue: "Permission denied" during packet capture
**Solution**: Run with sudo: `sudo venv/bin/python src/capture/packet_capture.py`

### Issue: "No module named 'database'"
**Solution**: Ensure you're in project root and database package exists

### Issue: Email alerts not sending
**Solution**: 
- Verify Gmail app password (not regular password)
- Check `config/email_config.json` settings
- Enable "Less secure app access" if using older Gmail

### Issue: Dashboard not showing attacks
**Solution**: 
- Ensure packet capture is running
- Check `data/live_results.json` has data
- Restart dashboard: `python src/dashboard/app_live.py`

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file for details

---

## 👨‍💻 Author

**Aashish Chaudhari**

AI-IDS Professional - Advanced Network Security with Machine Learning

---

## 🙏 Acknowledgments

- **CIC-IDS2017 Dataset**: Canadian Institute for Cybersecurity
- **Scapy**: Packet manipulation library
- **scikit-learn**: Machine learning framework
- **MITRE ATT&CK**: Threat intelligence framework
- **CVE Database**: NIST National Vulnerability Database

---

## 📚 Resources

- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE Database](https://nvd.nist.gov/)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Unauthorized network monitoring or intrusion detection may be illegal in your jurisdiction.

---

<div align="center">

**Built with ❤️ for Network Security**

[Report Bug](https://github.com/yourusername/AI-IDS-Project/issues) · [Request Feature](https://github.com/yourusername/AI-IDS-Project/issues)

</div>
