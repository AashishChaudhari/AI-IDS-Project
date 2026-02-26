#!/usr/bin/env python3
"""
AI-IDS Database Queries
Common database operations and queries
"""
from sqlalchemy import func, desc, and_, or_
from datetime import datetime, timedelta
from .models import get_session, Alert, TrafficLog, SystemEvent, AttackStatistics

class IDSDatabase:
    """Main database interface for IDS operations"""
    
    def __init__(self):
        self.session = get_session()
    
    def add_alert(self, attack_data):
        """Add a new alert to database"""
        try:
            # Determine threat level
            conf = attack_data['confidence']
            if conf >= 95:
                threat_level = 'CRITICAL'
            elif conf >= 85:
                threat_level = 'HIGH'
            elif conf >= 75:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            alert = Alert(
                timestamp=datetime.fromisoformat(attack_data['timestamp']),
                attack_type=attack_data['label'],
                confidence=attack_data['confidence'],
                threat_level=threat_level,
                source_ip=attack_data.get('src_ip', '0.0.0.0'),
                dest_ip=attack_data.get('dst_ip', '0.0.0.0'),
                source_port=attack_data.get('src_port', 0),
                dest_port=attack_data.get('dst_port', 0),
                protocol=attack_data.get('protocol', 'TCP'),
                fwd_packets=attack_data.get('fwd_pkts', 0),
                bwd_packets=attack_data.get('bwd_pkts', 0),
                total_bytes=attack_data.get('total_bytes', 0),
                detection_method=attack_data.get('detection_method', 'HYBRID'),
                model_version='1.0'
            )
            
            self.session.add(alert)
            self.session.commit()
            return alert.id
        except Exception as e:
            self.session.rollback()
            print(f"❌ Database error: {e}")
            return None
    
    def get_recent_alerts(self, limit=100):
        """Get most recent alerts"""
        return self.session.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()
    
    def get_alerts_by_type(self, attack_type, limit=50):
        """Get alerts of specific type"""
        return self.session.query(Alert).filter(Alert.attack_type == attack_type).order_by(desc(Alert.timestamp)).limit(limit).all()
    
    def get_alerts_in_timerange(self, start_time, end_time):
        """Get alerts within time range"""
        return self.session.query(Alert).filter(
            and_(Alert.timestamp >= start_time, Alert.timestamp <= end_time)
        ).order_by(desc(Alert.timestamp)).all()
    
    def get_critical_alerts(self, hours=24):
        """Get critical alerts from last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return self.session.query(Alert).filter(
            and_(Alert.threat_level == 'CRITICAL', Alert.timestamp >= cutoff)
        ).order_by(desc(Alert.timestamp)).all()
    
    def get_attack_statistics(self, hours=24):
        """Get attack statistics for last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        total = self.session.query(func.count(Alert.id)).filter(Alert.timestamp >= cutoff).scalar()
        
        by_type = self.session.query(
            Alert.attack_type,
            func.count(Alert.id).label('count')
        ).filter(Alert.timestamp >= cutoff).group_by(Alert.attack_type).all()
        
        by_severity = self.session.query(
            Alert.threat_level,
            func.count(Alert.id).label('count')
        ).filter(Alert.timestamp >= cutoff).group_by(Alert.threat_level).all()
        
        return {
            'total': total,
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'timerange': f'Last {hours} hours'
        }
    
    def log_traffic(self, stats):
        """Log traffic statistics"""
        try:
            log = TrafficLog(
                timestamp=datetime.now(),
                total_packets=stats.get('total_packets', 0),
                benign_packets=stats.get('benign_packets', 0),
                malicious_packets=stats.get('malicious_packets', 0),
                total_bytes=stats.get('total_bytes', 0),
                bytes_per_second=stats.get('bytes_per_second', 0.0),
                tcp_count=stats.get('tcp_count', 0),
                udp_count=stats.get('udp_count', 0),
                icmp_count=stats.get('icmp_count', 0),
                other_count=stats.get('other_count', 0)
            )
            self.session.add(log)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"❌ Traffic log error: {e}")
            return False
    
    def log_system_event(self, event_type, severity, message, details=None):
        """Log system event"""
        try:
            event = SystemEvent(
                timestamp=datetime.now(),
                event_type=event_type,
                severity=severity,
                message=message,
                details=details
            )
            self.session.add(event)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"❌ Event log error: {e}")
            return False
    
    def get_total_alerts(self):
        """Get total alert count"""
        return self.session.query(func.count(Alert.id)).scalar()
    
    def get_alert_count_today(self):
        """Get alert count for today"""
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.session.query(func.count(Alert.id)).filter(Alert.timestamp >= today).scalar()
    
    def search_alerts(self, search_term):
        """Search alerts by attack type or IP"""
        return self.session.query(Alert).filter(
            or_(
                Alert.attack_type.like(f'%{search_term}%'),
                Alert.source_ip.like(f'%{search_term}%'),
                Alert.dest_ip.like(f'%{search_term}%')
            )
        ).order_by(desc(Alert.timestamp)).limit(100).all()
    
    def close(self):
        """Close database session"""
        self.session.close()

# Convenience functions
def save_alert(alert_data):
    """Quick function to save an alert"""
    db = IDSDatabase()
    alert_id = db.add_alert(alert_data)
    db.close()
    return alert_id

def get_dashboard_stats():
    """Get statistics for dashboard"""
    db = IDSDatabase()
    stats = db.get_attack_statistics(hours=24)
    total_all_time = db.get_total_alerts()
    today_count = db.get_alert_count_today()
    db.close()
    
    return {
        'last_24h': stats,
        'total_all_time': total_all_time,
        'today': today_count
    }

if __name__ == "__main__":
    # Test database
    from models import init_database
    init_database()
    
    db = IDSDatabase()
    stats = db.get_attack_statistics()
    print(f"Total alerts: {db.get_total_alerts()}")
    print(f"Stats: {stats}")
    db.close()
