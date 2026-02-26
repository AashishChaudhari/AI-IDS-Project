#!/usr/bin/env python3
"""
AI-IDS Real-time Packet Capture with Database Integration
Hybrid Detection: ML Model + Behavioral Rules + SQLite Database Storage
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import sniff, IP, TCP, UDP, Raw
import pickle, json, time, argparse, os
from collections import defaultdict, deque
from datetime import datetime
import numpy as np
from colorama import Fore, Style, init

# Database integration
try:
    from database import save_alert, init_database
    DATABASE_ENABLED = True
    init_database()  # Initialize database on startup
except Exception as e:
    print(f"{Fore.YELLOW}⚠️  Database not available: {e}")
    DATABASE_ENABLED = False

init(autoreset=True)

# Base directory
BASE_DIR = Path('/home/aashish/AI-IDS-Project')
MODEL_PATH = BASE_DIR / 'models' / 'final_model.pkl'
SCALER_PATH = BASE_DIR / 'data' / 'processed' / 'scaler.pkl'
LABEL_ENCODER_PATH = BASE_DIR / 'data' / 'processed' / 'label_encoder.pkl'
FEATURE_NAMES_PATH = BASE_DIR / 'data' / 'processed' / 'feature_names.json'
SHARED_FILE = BASE_DIR / 'data' / 'live_results.json'

# Behavioral detection trackers
ddos_tracker = defaultdict(lambda: {'packets': deque(maxlen=100), 'last_seen': 0})
portscan_tracker = defaultdict(lambda: {'ports': set(), 'last_seen': 0})
ssh_brute_tracker = defaultdict(lambda: {'attempts': deque(maxlen=100), 'last_seen': 0})
http_payload_buffer = defaultdict(lambda: {'payloads': [], 'last_seen': 0})
slowloris_tracker = defaultdict(lambda: {'slow_connections': 0, 'last_seen': 0})

# Global counters
total_packets = 0
attack_count = 0

def load_model_components():
    """Load ML model and preprocessing components"""
    print(f"{Fore.YELLOW}Loading model components...")
    
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    
    with open(LABEL_ENCODER_PATH, 'rb') as f:
        label_encoder = pickle.load(f)
    
    with open(FEATURE_NAMES_PATH, 'r') as f:
        feature_names = json.load(f)
    
    print(f"{Fore.GREEN}✅ Model loaded: {len(feature_names)} features\n")
    return model, scaler, label_encoder, feature_names

def check_ssh_brute_force(pkt):
    """Detect SSH brute force - multiple connection attempts to port 22"""
    if not pkt.haslayer(TCP):
        return None
    
    tcp = pkt[TCP]
    if tcp.dport != 22 and tcp.sport != 22:
        return None
    
    src_ip = pkt[IP].src
    now = time.time()
    
    tracker = ssh_brute_tracker[src_ip]
    tracker['attempts'].append(now)
    tracker['last_seen'] = now
    
    # Count attempts in last 10 seconds
    recent = [t for t in tracker['attempts'] if now - t < 10]
    attempt_count = len(recent)
    
    # 10+ SSH connection attempts in 10 seconds = Brute Force
    if attempt_count >= 10:
        ssh_brute_tracker[src_ip]['attempts'].clear()
        return "SSH-Brute-Force", 22, attempt_count
    
    return None

def check_http_attacks(pkt):
    """Detect SQL Injection and XSS attacks in HTTP payloads"""
    if not pkt.haslayer(Raw):
        return None
    
    try:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
        
        # SQL Injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', '-- ', 'xp_cmdshell', 
                       '; exec', 'exec(', 'cast(', 'declare @']
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 
                       'document.cookie', 'eval(', '<iframe']
        
        src_ip = pkt[IP].src
        port = pkt[TCP].dport if pkt.haslayer(TCP) else 0
        
        attack_type = None
        
        # Check SQL Injection
        for pattern in sql_patterns:
            if pattern in payload:
                attack_type = "SQL-Injection"
                break
        
        # Check XSS if no SQLi found
        if not attack_type:
            for pattern in xss_patterns:
                if pattern in payload:
                    attack_type = "XSS-Attack"
                    break
        
        if attack_type:
            return attack_type, port, len(payload)
    
    except:
        pass
    
    return None

def check_slowloris(pkt):
    """Detect Slowloris - many slow incomplete HTTP connections"""
    if not pkt.haslayer(TCP):
        return None
    
    tcp = pkt[TCP]
    if tcp.dport not in [80, 443, 8080]:
        return None
    
    if tcp.flags & 0x02:  # SYN flag
        src_ip = pkt[IP].src
        tracker = slowloris_tracker[src_ip]
        tracker['slow_connections'] += 1
        tracker['last_seen'] = time.time()
        
        count = tracker['slow_connections']
        
        # 20+ slow connections from same source = Slowloris
        if count >= 20:
            slowloris_tracker[src_ip]['slow_connections'] = 0
            return "Slowloris-DoS", pkt[TCP].dport, count
    
    return None

def check_ddos(pkt):
    """Detect DDoS based on packet rate"""
    if not pkt.haslayer(IP):
        return None
    
    src_ip = pkt[IP].src
    now = time.time()
    
    tracker = ddos_tracker[src_ip]
    tracker['packets'].append(now)
    tracker['last_seen'] = now
    
    # Count packets in last second
    recent = [t for t in tracker['packets'] if now - t < 1]
    pkt_rate = len(recent)
    
    # >100 packets/second = DDoS
    if pkt_rate > 100:
        ddos_tracker[src_ip]['packets'].clear()
        return "DDoS", pkt[TCP].dport if pkt.haslayer(TCP) else 0, pkt_rate
    
    return None

def check_portscan(pkt):
    """Detect port scanning"""
    if not pkt.haslayer(TCP):
        return None
    
    tcp = pkt[TCP]
    src_ip = pkt[IP].src
    now = time.time()
    
    tracker = portscan_tracker[src_ip]
    tracker['ports'].add(tcp.dport)
    tracker['last_seen'] = now
    
    # Clean old entries
    if now - tracker['last_seen'] > 60:
        tracker['ports'].clear()
    
    unique_ports = len(tracker['ports'])
    
    # 10+ different ports = Port Scan
    if unique_ports >= 10:
        port_count = unique_ports
        portscan_tracker[src_ip]['ports'].clear()
        return "PortScan", tcp.dport, port_count
    
    return None

def extract_features(pkt):
    """Extract 78 features from packet for ML model"""
    features = [0] * 78
    
    if pkt.haslayer(IP):
        ip = pkt[IP]
        features[0] = ip.dst if pkt.haslayer(TCP) else 0  # Destination Port (simplified)
        features[1] = len(pkt)  # Flow Duration approximation
        
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            features[0] = tcp.dport
            features[44] = 1 if tcp.flags & 0x01 else 0  # FIN
            features[45] = 1 if tcp.flags & 0x02 else 0  # SYN
            features[46] = 1 if tcp.flags & 0x04 else 0  # RST
            features[47] = 1 if tcp.flags & 0x08 else 0  # PSH
            features[48] = 1 if tcp.flags & 0x10 else 0  # ACK
        
        features[2] = 1  # Total Fwd Packets
        features[3] = 0  # Total Backward Packets
        features[4] = len(pkt)  # Total Length
        features[14] = len(pkt)  # Flow Bytes/s approximation
        features[15] = 1  # Flow Packets/s approximation
    
    return np.array(features).reshape(1, -1)

def save_to_shared(data):
    """Save detection results to shared JSON file and database"""
    global attack_count
    
    # Save to JSON file (for dashboard compatibility)
    try:
        with open(SHARED_FILE, 'r') as f:
            shared = json.load(f)
    except:
        shared = {"traffic": [], "alerts": []}
    
    # Add to appropriate list
    if 'is_attack' in data and data['is_attack']:
        shared['alerts'].append(data)
        attack_count += 1
        
        # Save to database
        if DATABASE_ENABLED:
            try:
                alert_id = save_alert(data)
                if alert_id:
                    print(f"{Fore.GREEN}   💾 Saved to database (ID: {alert_id})")
            except Exception as e:
                print(f"{Fore.YELLOW}   ⚠️  Database save failed: {e}")
    else:
        shared['traffic'].append(data)
    
    # Keep only recent data
    shared['alerts'] = shared['alerts'][-500:]
    shared['traffic'] = shared['traffic'][-1000:]
    
    with open(SHARED_FILE, 'w') as f:
        json.dump(shared, f, indent=2)

def process_packet(pkt, model, scaler, label_encoder):
    """Process packet with hybrid detection"""
    global total_packets
    total_packets += 1
    
    if not pkt.haslayer(IP):
        return
    
    now = datetime.now().isoformat()
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    protocol = pkt[IP].proto
    
    # Behavioral rule-based detection (checked first for speed)
    behavioral_result = None
    
    # Check each behavioral detector
    for detector in [check_ddos, check_portscan, check_ssh_brute_force, check_http_attacks, check_slowloris]:
        result = detector(pkt)
        if result:
            behavioral_result = result
            break
    
    # If behavioral detection found something
    if behavioral_result:
        attack_type, port, metric = behavioral_result
        
        alert_data = {
            'timestamp': now,
            'label': attack_type,
            'confidence': 98,  # Behavioral rules are high confidence
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else 0,
            'dst_port': port,
            'protocol': 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'OTHER',
            'fwd_pkts': 1,
            'bwd_pkts': 0,
            'total_bytes': len(pkt),
            'is_attack': True,
            'detection_method': 'RULE'
        }
        
        save_to_shared(alert_data)
        
        color = Fore.RED if alert_data['confidence'] >= 95 else Fore.YELLOW
        print(f"{color}🚨 {attack_type} detected from {src_ip}:{port} (Rule-based: {metric})")
        return
    
    # ML detection (only for packets that pass behavioral rules)
    if total_packets % 10 == 0:  # ML every 10th packet to save resources
        try:
            features = extract_features(pkt)
            features_scaled = scaler.transform(features)
            
            prediction = model.predict(features_scaled)[0]
            proba = model.predict_proba(features_scaled)[0]
            confidence = int(max(proba) * 100)
            label = label_encoder.inverse_transform([prediction])[0]
            
            # Only alert if not BENIGN and confidence > 75%
            if label != 'BENIGN' and confidence > 75:
                alert_data = {
                    'timestamp': now,
                    'label': label,
                    'confidence': confidence,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else 0,
                    'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else 0,
                    'protocol': 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'OTHER',
                    'fwd_pkts': 1,
                    'bwd_pkts': 0,
                    'total_bytes': len(pkt),
                    'is_attack': True,
                    'detection_method': 'ML'
                }
                
                save_to_shared(alert_data)
                
                color = Fore.RED if confidence >= 95 else Fore.YELLOW
                print(f"{color}🚨 {label} detected from {src_ip} (ML: {confidence}%)")
        except Exception as e:
            pass  # Skip ML errors silently
    
    # Log normal traffic periodically
    if total_packets % 100 == 0:
        traffic_data = {
            'timestamp': now,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'OTHER',
            'fwd_pkts': 1,
            'bwd_pkts': 0,
            'is_attack': False
        }
        save_to_shared(traffic_data)

def main():
    parser = argparse.ArgumentParser(description='AI-IDS Real-time Packet Capture with Database')
    parser.add_argument('--iface', type=str, default='eth0', help='Network interface')
    parser.add_argument('--filter', type=str, default='', help='BPF filter')
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}  AI-IDS CAPTURE (Hybrid Detection + Database Storage)")
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.YELLOW}  Interface: {args.iface}")
    print(f"{Fore.YELLOW}  DDoS: >100 pkt/s | PortScan: 10+ ports")
    print(f"{Fore.YELLOW}  SQLi/XSS: Payload analysis | SSH Brute: 10+ attempts")
    if DATABASE_ENABLED:
        print(f"{Fore.GREEN}  Database: ✅ Enabled (SQLite)")
    else:
        print(f"{Fore.RED}  Database: ❌ Disabled")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    model, scaler, label_encoder, feature_names = load_model_components()
    
    print(f"{Fore.GREEN}🎯 Monitoring started. Press Ctrl+C to stop.\n")
    
    try:
        sniff(
            iface=args.iface,
            prn=lambda pkt: process_packet(pkt, model, scaler, label_encoder),
            filter=args.filter,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}📊 Session Summary:")
        print(f"{Fore.GREEN}   Total Packets: {total_packets:,}")
        print(f"{Fore.RED}   Attacks Detected: {attack_count}")
        if DATABASE_ENABLED:
            print(f"{Fore.GREEN}   Database: All attacks saved to SQLite")
        print(f"{Fore.CYAN}{'='*70}\n")

if __name__ == "__main__":
    main()
