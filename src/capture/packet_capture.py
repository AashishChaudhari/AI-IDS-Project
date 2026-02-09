#!/usr/bin/env python3
import os, sys, time, json, pickle, threading
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from colorama import Fore, init
init(autoreset=True)

BASE = Path('/home/aashish/AI-IDS-Project')
SHARED = BASE / 'data' / 'live_results.json'

print(f"{Fore.CYAN}Loading model...")
with open(BASE/'models'/'final_model.pkl','rb') as f:
    model = pickle.load(f)
with open(BASE/'data'/'processed'/'label_encoder.pkl','rb') as f:
    label_encoder = pickle.load(f)
with open(BASE/'data'/'processed'/'scaler.pkl','rb') as f:
    scaler = pickle.load(f)
with open(BASE/'data'/'processed'/'feature_names.json') as f:
    feature_names = json.load(f)
CLASSES = label_encoder.classes_.tolist()
print(f"{Fore.GREEN}✅ Model loaded\n")

traffic = []
alerts  = []
packet_rate_tracker = defaultdict(lambda: deque(maxlen=1000))

def save():
    tmp = str(SHARED)+'.tmp'
    with open(tmp,'w') as f:
        json.dump({"traffic": traffic[-200:], "alerts": alerts}, f)
    os.replace(tmp, str(SHARED))
save()

class Flow:
    def __init__(self):
        self.start=self.end=None;self.fwd_pkts=self.bwd_pkts=0;self.fwd_bytes=self.bwd_bytes=0
        self.fwd_lens=[];self.bwd_lens=[];self.fwd_iat=[];self.bwd_iat=[]
        self.last_fwd=self.last_bwd=None;self.syn=self.ack=self.fin=self.rst=self.psh=self.urg=self.ece=self.cwr=0
        self.fwd_wins=[];self.bwd_wins=[];self.fwd_hdrs=[];self.bwd_hdrs=[];self.dst_port=0;self.proto=0

active_flows={};completed=deque(maxlen=1000);flow_lock=threading.Lock();FLOW_TIMEOUT=3

def get_flow_key(pkt):
    src,dst=pkt[IP].src,pkt[IP].dst;sp=dp=0;proto=pkt[IP].proto
    if pkt.haslayer(TCP):sp,dp=pkt[TCP].sport,pkt[TCP].dport
    elif pkt.haslayer(UDP):sp,dp=pkt[UDP].sport,pkt[UDP].dport
    return((src,sp,dst,dp,proto),'fwd')if(src,sp)<=(dst,dp)else((dst,dp,src,sp,proto),'bwd')

def check_rate_based_attack(pkt):
    """Check if packet rate indicates flood attack"""
    if not pkt.haslayer(IP):
        return None
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    now = time.time()
    
    # Track packets from this source in the last 1 second
    packet_rate_tracker[src_ip].append(now)
    
    # Remove old packets (older than 1 second)
    while packet_rate_tracker[src_ip] and now - packet_rate_tracker[src_ip][0] > 1.0:
        packet_rate_tracker[src_ip].popleft()
    
    rate = len(packet_rate_tracker[src_ip])
    
    # If more than 100 packets per second from same source = FLOOD
    if rate > 100:
        port = 0
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
            # SYN flood detection
            if pkt[TCP].flags & 0x02:
                return "DDoS", port, rate
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport
            return "DDoS", port, rate
    
    return None

def add_packet(pkt):
    # Check for rate-based attack FIRST
    rate_attack = check_rate_based_attack(pkt)
    if rate_attack:
        attack_type, port, rate = rate_attack
        entry = {
            "timestamp": datetime.now().isoformat(),
            "label": attack_type,
            "confidence": 99.0,
            "is_attack": True,
            "fwd_pkts": rate,
            "bwd_pkts": 0,
            "duration": 1.0,
            "dst_port": port
        }
        traffic.append(entry)
        if len(traffic) > 200:
            traffic.pop(0)
        alerts.append(entry)
        print(f"{Fore.RED}🚨 ATTACK | {attack_type:12s} | rate={rate:4d} pkt/s | port={port}")
        save()
        return
    
    if not pkt.haslayer(IP):
        return
    key, d = get_flow_key(pkt)
    now = time.time()
    plen = len(pkt)

    with flow_lock:
        if key not in active_flows:
            active_flows[key] = Flow()
            active_flows[key].start = now
            active_flows[key].proto = pkt[IP].proto
            if pkt.haslayer(TCP):
                active_flows[key].dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                active_flows[key].dst_port = pkt[UDP].dport

        fl = active_flows[key]
        fl.end = now

        if d == 'fwd':
            fl.fwd_pkts += 1
            fl.fwd_bytes += plen
            fl.fwd_lens.append(plen)
            if fl.last_fwd:
                fl.fwd_iat.append(now - fl.last_fwd)
            fl.last_fwd = now
            if pkt.haslayer(TCP):
                fl.fwd_wins.append(pkt[TCP].window)
                fl.fwd_hdrs.append((pkt[TCP].dataofs or 5)*4)
        else:
            fl.bwd_pkts += 1
            fl.bwd_bytes += plen
            fl.bwd_lens.append(plen)
            if fl.last_bwd:
                fl.bwd_iat.append(now - fl.last_bwd)
            fl.last_bwd = now
            if pkt.haslayer(TCP):
                fl.bwd_wins.append(pkt[TCP].window)
                fl.bwd_hdrs.append((pkt[TCP].dataofs or 5)*4)

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x02: fl.syn += 1
            if flags & 0x10: fl.ack += 1
            if flags & 0x01: fl.fin += 1
            if flags & 0x04: fl.rst += 1
            if flags & 0x08: fl.psh += 1
            if flags & 0x20: fl.urg += 1
            if flags & 0x40: fl.ece += 1
            if flags & 0x80: fl.cwr += 1
            if(flags & 0x01)or(flags & 0x04):
                completed.append(active_flows.pop(key))

def expire_flows():
    now = time.time()
    with flow_lock:
        expired = [k for k,fl in active_flows.items() if fl.end and (now - fl.end) > FLOW_TIMEOUT]
        for k in expired:
            completed.append(active_flows.pop(k))

m = lambda l: float(np.mean(l)) if l else 0.0
s = lambda l: float(np.std(l)) if l else 0.0
mx = lambda l: float(max(l)) if l else 0.0
mn = lambda l: float(min(l)) if l else 0.0

def extract(fl):
    dur = (fl.end - fl.start) if fl.end and fl.start else 0.0
    tf = fl.fwd_pkts
    tb = fl.bwd_pkts
    all_lens = fl.fwd_lens + fl.bwd_lens
    all_iat = fl.fwd_iat + fl.bwd_iat
    feat = {'Destination Port': float(fl.dst_port), 'Flow Duration': dur, 'Total Fwd Packets': float(tf), 'Total Backward Packets': float(tb), 'Total Length of Fwd Packets': float(fl.fwd_bytes), 'Total Length of Bwd Packets': float(fl.bwd_bytes), 'Fwd Packet Length Max': mx(fl.fwd_lens), 'Fwd Packet Length Min': mn(fl.fwd_lens), 'Fwd Packet Length Mean': m(fl.fwd_lens), 'Fwd Packet Length Std': s(fl.fwd_lens), 'Bwd Packet Length Max': mx(fl.bwd_lens), 'Bwd Packet Length Min': mn(fl.bwd_lens), 'Bwd Packet Length Mean': m(fl.bwd_lens), 'Bwd Packet Length Std': s(fl.bwd_lens), 'Flow Bytes/s': (fl.fwd_bytes + fl.bwd_bytes) / dur if dur > 0 else float(fl.fwd_bytes + fl.bwd_bytes), 'Flow Packets/s': (tf + tb) / dur if dur > 0 else float(tf + tb), 'Flow IAT Mean': m(all_iat), 'Flow IAT Std': s(all_iat), 'Flow IAT Max': mx(all_iat), 'Flow IAT Min': mn(all_iat), 'Fwd IAT Total': sum(fl.fwd_iat) if fl.fwd_iat else 0.0, 'Fwd IAT Mean': m(fl.fwd_iat), 'Fwd IAT Std': s(fl.fwd_iat), 'Fwd IAT Max': mx(fl.fwd_iat), 'Fwd IAT Min': mn(fl.fwd_iat), 'Bwd IAT Total': sum(fl.bwd_iat) if fl.bwd_iat else 0.0, 'Bwd IAT Mean': m(fl.bwd_iat), 'Bwd IAT Std': s(fl.bwd_iat), 'Bwd IAT Max': mx(fl.bwd_iat), 'Bwd IAT Min': mn(fl.bwd_iat), 'Fwd SYN Flag Count': float(fl.syn), 'Fwd PSH Flag Count': float(fl.psh), 'Fwd ACK Flag Count': float(fl.ack), 'Fwd URG Flag Count': float(fl.urg), 'Fwd FIN Flag Count': float(fl.fin), 'Bwd PSH Flag Count': 0.0, 'Bwd ACK Flag Count': 0.0, 'Bwd URG Flag Count': 0.0, 'Bwd FIN Flag Count': 0.0, 'Bwd SYN Flag Count': 0.0, 'Bwd RST Flag Count': float(fl.rst), 'Bwd ECE Flag Count': float(fl.ece), 'Length Flag Count': 0.0, 'Packet Length Max': max(mx(fl.fwd_lens), mx(fl.bwd_lens)), 'Packet Length Min': min(mn(fl.fwd_lens) if fl.fwd_lens else 9999, mn(fl.bwd_lens) if fl.bwd_lens else 9999), 'Packet Length Mean': m(all_lens), 'Packet Length Std': s(all_lens), 'Packet Length Var': float(np.var(all_lens)) if all_lens else 0.0, 'ACK Flag Count': float(fl.ack), 'URG Flag Count': float(fl.urg), 'CWE Flag Count': float(fl.cwr), 'ECE Flag Count': float(fl.ece), 'Down/Up Ratio': float(tb) / tf if tf > 0 else 0.0, 'Fwd Bytes/Bulk Avg': 0.0, 'Fwd Packets/Bulk Avg': 0.0, 'Fwd Bulk Rate Avg': 0.0, 'Bwd Bytes/Bulk Avg': 0.0, 'Bwd Packets/Bulk Avg': 0.0, 'Bwd Bulk Rate Avg': 0.0, 'Subflow Fwd Packets': float(tf), 'Subflow Fwd Bytes': float(fl.fwd_bytes), 'Subflow Bwd Packets': float(tb), 'Subflow Bwd Bytes': float(fl.bwd_bytes), 'Init_Win_bytes_fwd': m(fl.fwd_wins), 'Init_Win_bytes_bwd': m(fl.bwd_wins), 'act_data_fwd_len': max(0.0, float(fl.fwd_bytes) - m(fl.fwd_hdrs) * tf), 'min_seg_size_fwd': mn(fl.fwd_hdrs), 'Inbound': 0.0}
    return np.array([feat.get(fn, 0.0) for fn in feature_names], dtype=np.float64)

def predict(fl):
    feats = np.nan_to_num(extract(fl), nan=0.0, posinf=0.0, neginf=0.0)
    scaled = scaler.transform(feats.reshape(1, -1))
    idx = model.predict(scaled)[0]
    prob = model.predict_proba(scaled)[0]
    return CLASSES[idx], round(float(prob[idx]) * 100, 2)

def worker():
    while True:
        time.sleep(0.5)
        expire_flows()
        while completed:
            try:
                fl = completed.popleft()
            except IndexError:
                break
            if fl.fwd_pkts + fl.bwd_pkts < 5:
                continue
            label, conf = predict(fl)
            entry = {"timestamp": datetime.now().isoformat(), "label": label, "confidence": conf, "is_attack": label != "BENIGN", "fwd_pkts": fl.fwd_pkts, "bwd_pkts": fl.bwd_pkts, "duration": round((fl.end - fl.start), 3) if fl.end and fl.start else 0, "dst_port": fl.dst_port}
            traffic.append(entry)
            if len(traffic) > 200:
                traffic.pop(0)
            if entry["is_attack"]:
                alerts.append(entry)
                print(f"{Fore.RED}🚨 ATTACK | {label:12s} | conf={conf:5.1f}% | pkts={fl.fwd_pkts + fl.bwd_pkts:5d} | port={fl.dst_port}")
            save()

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default=None)
    args = parser.parse_args()
    if not args.iface:
        ifaces = [i for i in get_if_list() if i != 'lo']
        args.iface = ifaces[0] if ifaces else 'eth0'
    print(f"{Fore.CYAN}{'=' * 60}\n  AI-IDS CAPTURE (Rate-Based Detection)\n{'=' * 60}\n  Interface: {args.iface}\n{'=' * 60}\n")
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        sniff(iface=args.iface, prn=add_packet, filter="ip", store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopping...")
        save()
        print(f"{Fore.GREEN}✅ Done. Alerts: {len(alerts)}")

if __name__ == '__main__':
    main()
