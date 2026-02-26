#!/usr/bin/env python3
"""
AI-IDS Database Models
SQLAlchemy models for storing all IDS data
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from pathlib import Path

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
DB_PATH = BASE_DIR / 'data' / 'ids_database.db'

Base = declarative_base()

class Alert(Base):
    """Detected attacks/threats"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    attack_type = Column(String(50), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    threat_level = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Network details
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    
    # Packet statistics
    fwd_packets = Column(Integer, default=0)
    bwd_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    
    # Detection metadata
    detection_method = Column(String(20))  # ML, RULE, HYBRID
    model_version = Column(String(20))
    
    # Response tracking
    email_sent = Column(Boolean, default=False)
    action_taken = Column(String(100))
    notes = Column(Text)
    
    created_at = Column(DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<Alert {self.id}: {self.attack_type} @ {self.timestamp}>"


class TrafficLog(Base):
    """Network traffic statistics"""
    __tablename__ = 'traffic_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    
    # Traffic counts
    total_packets = Column(Integer, default=0)
    benign_packets = Column(Integer, default=0)
    malicious_packets = Column(Integer, default=0)
    
    # Bandwidth
    total_bytes = Column(Integer, default=0)
    bytes_per_second = Column(Float, default=0.0)
    
    # Protocol breakdown
    tcp_count = Column(Integer, default=0)
    udp_count = Column(Integer, default=0)
    icmp_count = Column(Integer, default=0)
    other_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<TrafficLog {self.id}: {self.total_packets} pkts @ {self.timestamp}>"


class SystemEvent(Base):
    """System events and status changes"""
    __tablename__ = 'system_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # START, STOP, ERROR, CONFIG_CHANGE
    severity = Column(String(20))  # INFO, WARNING, ERROR, CRITICAL
    message = Column(Text)
    details = Column(Text)
    
    created_at = Column(DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<SystemEvent {self.id}: {self.event_type} @ {self.timestamp}>"


class AttackStatistics(Base):
    """Aggregated attack statistics (hourly/daily)"""
    __tablename__ = 'attack_statistics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False)
    period_type = Column(String(10))  # HOURLY, DAILY, WEEKLY
    
    # Attack counts by type
    ddos_count = Column(Integer, default=0)
    portscan_count = Column(Integer, default=0)
    bot_count = Column(Integer, default=0)
    sqli_count = Column(Integer, default=0)
    xss_count = Column(Integer, default=0)
    ssh_bruteforce_count = Column(Integer, default=0)
    slowloris_count = Column(Integer, default=0)
    
    total_attacks = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    
    # Severity breakdown
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<AttackStats {self.period_start} - {self.period_end}>"


# Database engine and session
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
Session = sessionmaker(bind=engine)

def init_database():
    """Initialize database and create all tables"""
    Base.metadata.create_all(engine)
    print(f"✅ Database initialized: {DB_PATH}")

def get_session():
    """Get a new database session"""
    return Session()

if __name__ == "__main__":
    init_database()
