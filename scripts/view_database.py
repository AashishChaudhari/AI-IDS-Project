#!/usr/bin/env python3
"""
AI-IDS Database Viewer
Query and view database contents
"""
import sys
sys.path.insert(0, '/home/aashish/AI-IDS-Project/src')

from database import IDSDatabase
from datetime import datetime, timedelta
from colorama import Fore, Style, init

init(autoreset=True)

def main():
    db = IDSDatabase()
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}  🗄️  AI-IDS DATABASE VIEWER")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    # Overall statistics
    total = db.get_total_alerts()
    today = db.get_alert_count_today()
    
    print(f"{Fore.GREEN}📊 Overall Statistics:")
    print(f"   Total Alerts (All Time): {total:,}")
    print(f"   Alerts Today: {today:,}\n")
    
    # Last 24 hours stats
    stats = db.get_attack_statistics(hours=24)
    
    print(f"{Fore.YELLOW}📈 Last 24 Hours:")
    print(f"   Total Attacks: {stats['total']:,}")
    
    if stats['by_type']:
        print(f"\n   {Fore.CYAN}By Type:")
        for attack_type, count in stats['by_type'].items():
            print(f"      {attack_type}: {count}")
    
    if stats['by_severity']:
        print(f"\n   {Fore.CYAN}By Severity:")
        for severity, count in stats['by_severity'].items():
            color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity == 'HIGH' else Fore.GREEN
            print(f"      {color}{severity}: {count}")
    
    # Recent alerts
    print(f"\n{Fore.MAGENTA}🚨 Recent Alerts (Last 10):")
    recent = db.get_recent_alerts(limit=10)
    
    if recent:
        print(f"\n   {'Time':<12} {'Type':<20} {'Confidence':<12} {'Threat':<10} {'Port':<6}")
        print(f"   {'-'*62}")
        for alert in recent:
            color = Fore.RED if alert.threat_level == 'CRITICAL' else Fore.YELLOW if alert.threat_level == 'HIGH' else Fore.GREEN
            print(f"   {alert.timestamp.strftime('%H:%M:%S'):<12} {alert.attack_type:<20} {alert.confidence:.1f}%{' ':<8} {color}{alert.threat_level:<10}{Style.RESET_ALL} {alert.dest_port or 'N/A':<6}")
    else:
        print(f"   {Fore.YELLOW}No alerts found in database")
    
    db.close()
    print(f"\n{Fore.CYAN}{'='*70}\n")

if __name__ == "__main__":
    main()
