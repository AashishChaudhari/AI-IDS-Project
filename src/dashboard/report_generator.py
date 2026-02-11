#!/usr/bin/env python3
"""Enhanced PDF Report Generator with Charts"""
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER

BASE_DIR = Path('/home/aashish/AI-IDS-Project')
REPORTS_DIR = BASE_DIR / 'reports'
TEMP_DIR = REPORTS_DIR / 'temp'
REPORTS_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

class IDSReportGenerator:
    def __init__(self, alerts_data):
        self.alerts = alerts_data
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        
    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=self.styles['Title'],
            fontSize=32,
            textColor=HexColor('#1a5276'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=HexColor('#1a5276'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Subsection',
            parent=self.styles['Heading2'],
            fontSize=13,
            textColor=HexColor('#2874a6'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))

    def _create_traffic_timeline_chart(self):
        """Create traffic timeline chart matching dashboard"""
        now = datetime.now()
        labels = [(now - timedelta(minutes=i)).strftime('%H:%M') for i in range(59, -1, -1)]
        
        attack_counts = [0] * 60
        normal_counts = [0] * 60
        
        # Load traffic data
        try:
            with open(BASE_DIR / 'data' / 'live_results.json', 'r') as f:
                data = json.load(f)
                traffic = data.get('traffic', [])
                
            for t in traffic[-200:]:
                ts = datetime.fromisoformat(t['timestamp'])
                mins_ago = int((now - ts).seconds / 60)
                if mins_ago < 60:
                    if t['is_attack']:
                        attack_counts[59 - mins_ago] += 1
                    else:
                        normal_counts[59 - mins_ago] += 1
        except:
            pass
        
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.plot(labels, normal_counts, 'g-', label='Normal Traffic', linewidth=2, marker='o', markersize=3)
        ax.plot(labels, attack_counts, 'r-', label='Attacks', linewidth=2, marker='s', markersize=3)
        ax.set_xlabel('Time', fontsize=11, fontweight='bold')
        ax.set_ylabel('Packet Count', fontsize=11, fontweight='bold')
        ax.set_title('Real-Time Traffic Monitor (Last Hour)', fontsize=13, fontweight='bold')
        ax.legend(loc='upper left')
        ax.grid(True, alpha=0.3)
        
        # Show every 10th label to avoid crowding
        ax.set_xticks(range(0, 60, 10))
        ax.set_xticklabels([labels[i] for i in range(0, 60, 10)], rotation=45)
        
        chart_path = TEMP_DIR / 'traffic_timeline.png'
        fig.tight_layout()
        fig.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        
        return chart_path

    def _create_attack_distribution_chart(self):
        """Create attack distribution pie chart"""
        if not self.alerts:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.text(0.5, 0.5, 'No Attacks Detected', ha='center', va='center', fontsize=14)
            ax.axis('off')
            chart_path = TEMP_DIR / 'attack_dist.png'
            fig.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close(fig)
            return chart_path
        
        attack_counts = Counter(a['label'] for a in self.alerts)
        
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = {'DDoS': '#ef4444', 'PortScan': '#f59e0b', 'Bot': '#a855f7'}
        pie_colors = [colors.get(k, '#64748b') for k in attack_counts.keys()]
        
        wedges, texts, autotexts = ax.pie(
            attack_counts.values(), 
            labels=attack_counts.keys(), 
            autopct='%1.1f%%',
            startangle=90,
            colors=pie_colors,
            textprops={'fontsize': 11, 'fontweight': 'bold'}
        )
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        ax.set_title('Attack Distribution', fontsize=13, fontweight='bold')
        
        chart_path = TEMP_DIR / 'attack_dist.png'
        fig.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        
        return chart_path

    def _create_attack_types_bar_chart(self):
        """Create bar chart of attack types"""
        if not self.alerts:
            return None
        
        attack_counts = Counter(a['label'] for a in self.alerts)
        
        fig, ax = plt.subplots(figsize=(7, 4))
        colors = {'DDoS': '#ef4444', 'PortScan': '#f59e0b', 'Bot': '#a855f7'}
        bar_colors = [colors.get(k, '#64748b') for k in attack_counts.keys()]
        
        bars = ax.bar(attack_counts.keys(), attack_counts.values(), color=bar_colors, edgecolor='black', linewidth=1.5)
        
        ax.set_ylabel('Number of Attacks', fontsize=11, fontweight='bold')
        ax.set_title('Attack Types Breakdown', fontsize=13, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontweight='bold', fontsize=10)
        
        chart_path = TEMP_DIR / 'attack_types.png'
        fig.tight_layout()
        fig.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        
        return chart_path

    def _create_confidence_histogram(self):
        """Create histogram of attack confidence levels"""
        if not self.alerts:
            return None
        
        confidences = [a['confidence'] for a in self.alerts]
        
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.hist(confidences, bins=20, color='#3b82f6', edgecolor='black', alpha=0.7)
        ax.set_xlabel('Confidence Level (%)', fontsize=11, fontweight='bold')
        ax.set_ylabel('Frequency', fontsize=11, fontweight='bold')
        ax.set_title('Attack Detection Confidence Distribution', fontsize=13, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        # Add mean line
        mean_conf = np.mean(confidences)
        ax.axvline(mean_conf, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_conf:.1f}%')
        ax.legend()
        
        chart_path = TEMP_DIR / 'confidence_hist.png'
        fig.tight_layout()
        fig.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        
        return chart_path

    def generate_report(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"AI_IDS_Report_{timestamp}.pdf"
        filepath = REPORTS_DIR / filename
        
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # ═══════════════════════════════════════════════════════
        # COVER PAGE
        # ═══════════════════════════════════════════════════════
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("AI-Powered Intrusion Detection System", self.styles['CoverTitle']))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(f"<b>Developed by:</b> Aashish Chaudhari", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(f"<b>Version:</b> 1.0 | <b>Model:</b> Random Forest", self.styles['Normal']))
        story.append(PageBreak())
        
        # ═══════════════════════════════════════════════════════
        # EXECUTIVE SUMMARY
        # ═══════════════════════════════════════════════════════
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        summary = f"""
        This AI-powered Intrusion Detection System employs machine learning to detect network threats 
        in real-time. The system achieved <b>99.81% accuracy</b> on the CIC-IDS2017 benchmark dataset and 
        is currently monitoring live network traffic with hybrid detection (ML + rate-based analysis).
        <br/><br/>
        <b>Current Session Statistics:</b><br/>
        • Total Attacks Detected: <b>{len(self.alerts)}</b><br/>
        • Detection Method: Hybrid (Machine Learning + Rate-based Analysis)<br/>
        • Model: Random Forest Classifier (200 trees)<br/>
        • Dataset: CIC-IDS2017 (470,547 samples, 78 features)
        """
        story.append(Paragraph(summary, self.styles['Normal']))
        story.append(PageBreak())
        
        # ═══════════════════════════════════════════════════════
        # LIVE TRAFFIC CHARTS
        # ═══════════════════════════════════════════════════════
        story.append(Paragraph("Real-Time Traffic Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Traffic Timeline
        story.append(Paragraph("<b>Traffic Timeline (Last Hour)</b>", self.styles['Subsection']))
        traffic_chart = self._create_traffic_timeline_chart()
        story.append(Image(str(traffic_chart), width=6.5*inch, height=3.25*inch))
        story.append(Spacer(1, 0.3*inch))
        
        # Attack Distribution
        story.append(Paragraph("<b>Attack Distribution</b>", self.styles['Subsection']))
        dist_chart = self._create_attack_distribution_chart()
        story.append(Image(str(dist_chart), width=5*inch, height=3.3*inch))
        story.append(PageBreak())
        
        # ═══════════════════════════════════════════════════════
        # ATTACK STATISTICS
        # ═══════════════════════════════════════════════════════
        if self.alerts:
            story.append(Paragraph("Attack Statistics", self.styles['SectionHeader']))
            story.append(Spacer(1, 0.2*inch))
            
            attack_counts = Counter(a['label'] for a in self.alerts)
            
            # Summary Table
            summary_data = [
                ['Metric', 'Value'],
                ['Total Attacks', str(len(self.alerts))],
                ['DDoS Attacks', str(attack_counts.get('DDoS', 0))],
                ['Port Scans', str(attack_counts.get('PortScan', 0))],
                ['Bot Activity', str(attack_counts.get('Bot', 0))],
                ['Average Confidence', f"{sum(a['confidence'] for a in self.alerts)/len(self.alerts):.1f}%"]
            ]
            
            t = Table(summary_data, colWidths=[3*inch, 3*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), HexColor('#2e86c1')),
                ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 11),
                ('BACKGROUND', (0,1), (-1,-1), HexColor('#eaf2f8')),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#aed6f1')),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.3*inch))
            
            # Attack Types Bar Chart
            bar_chart = self._create_attack_types_bar_chart()
            if bar_chart:
                story.append(Paragraph("<b>Attack Types Breakdown</b>", self.styles['Subsection']))
                story.append(Image(str(bar_chart), width=5.5*inch, height=3.14*inch))
                story.append(Spacer(1, 0.3*inch))
            
            # Confidence Histogram
            conf_chart = self._create_confidence_histogram()
            if conf_chart:
                story.append(Paragraph("<b>Detection Confidence Distribution</b>", self.styles['Subsection']))
                story.append(Image(str(conf_chart), width=5.5*inch, height=3.14*inch))
            
            story.append(PageBreak())
            
            # Recent Alerts Table
            story.append(Paragraph("Recent Attack Details", self.styles['SectionHeader']))
            story.append(Spacer(1, 0.2*inch))
            
            alert_data = [['Time', 'Attack Type', 'Confidence', 'Port', 'Packets']]
            for a in self.alerts[-25:]:
                alert_data.append([
                    datetime.fromisoformat(a['timestamp']).strftime('%H:%M:%S'),
                    a['label'],
                    f"{a['confidence']}%",
                    str(a.get('dst_port', '—')),
                    str(a['fwd_pkts'] + a['bwd_pkts'])
                ])
            
            t2 = Table(alert_data, colWidths=[1.2*inch, 1.5*inch, 1.2*inch, 0.8*inch, 1*inch])
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), HexColor('#e74c3c')),
                ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('BACKGROUND', (0,1), (-1,-1), HexColor('#fadbd8')),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#e74c3c')),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('ALIGN', (0,0), (-1,-1), 'CENTER')
            ]))
            story.append(t2)
        else:
            story.append(Paragraph("Attack Statistics", self.styles['SectionHeader']))
            story.append(Paragraph("No attacks detected in current monitoring session.", self.styles['Normal']))
        
        story.append(PageBreak())
        
        # ═══════════════════════════════════════════════════════
        # MODEL PERFORMANCE
        # ═══════════════════════════════════════════════════════
        story.append(Paragraph("Model Performance Metrics", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        perf_data = [
            ['Metric', 'Value'],
            ['Overall Accuracy', '99.81%'],
            ['Precision (Weighted)', '99.82%'],
            ['Recall (Weighted)', '99.81%'],
            ['F1-Score', '99.81%'],
            ['Test Samples', '94,110'],
            ['Training Time', '2.4 minutes'],
            ['False Positive Rate', '0.19%']
        ]
        
        t3 = Table(perf_data, colWidths=[3*inch, 3*inch])
        t3.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#27ae60')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 11),
            ('BACKGROUND', (0,1), (-1,-1), HexColor('#d5f4e6')),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#27ae60')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t3)
        story.append(Spacer(1, 0.3*inch))
        
        # Per-Class Performance
        story.append(Paragraph("<b>Per-Class Performance</b>", self.styles['Subsection']))
        class_data = [
            ['Class', 'Precision', 'Recall', 'F1-Score'],
            ['BENIGN', '1.00', '1.00', '1.00'],
            ['DDoS', '1.00', '1.00', '1.00'],
            ['PortScan', '1.00', '1.00', '1.00'],
            ['Bot', '0.49', '0.96', '0.65']
        ]
        
        t4 = Table(class_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        t4.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#34495e')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BACKGROUND', (0,1), (-1,-1), HexColor('#ecf0f1')),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#95a5a6')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        story.append(t4)
        story.append(PageBreak())
        
        # ═══════════════════════════════════════════════════════
        # CONCLUSION
        # ═══════════════════════════════════════════════════════
        story.append(Paragraph("Conclusion", self.styles['SectionHeader']))
        conclusion = """
        The AI-IDS system demonstrates high accuracy in detecting network intrusions with minimal 
        false positives. The hybrid detection approach (machine learning + rate-based analysis) 
        provides comprehensive coverage against both known attack patterns and volumetric threats.
        <br/><br/>
        <b>System Status:</b> Operational and monitoring live traffic<br/>
        <b>Deployment:</b> Production-ready prototype<br/>
        <b>Recommendation:</b> Continue monitoring with periodic model retraining (quarterly)
        <br/><br/>
        <b>Contact:</b> Aashish Chaudhari | chaudhariaashish18@email.com<br/>
        <b>Repository:</b> github.com/AashishChaudhari/AI-IDS-Project
        """
        story.append(Paragraph(conclusion, self.styles['Normal']))
        
        doc.build(story)
        
        # Cleanup temp charts
        for f in TEMP_DIR.glob('*.png'):
            f.unlink()
        
        return filename
