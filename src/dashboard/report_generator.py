#!/usr/bin/env python3
"""
AI-IDS Professional Report Generator
Generates comprehensive PDF security reports with enhanced visualizations
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from datetime import datetime
from pathlib import Path
from collections import Counter
import io
import os

# Import ReportLab
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas

class IDSReportGenerator:
    def __init__(self, alerts):
        self.alerts = alerts
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.filename = f"AI_IDS_Report_{self.timestamp}.pdf"
        self.filepath = Path(f"/home/aashish/AI-IDS-Project/reports/{self.filename}")
        
    def create_attack_distribution_chart(self):
        """Create professional attack distribution pie chart without overlapping labels"""
        attack_counts = Counter(a['label'] for a in self.alerts)
        
        if not attack_counts:
            return None
        
        # Professional color scheme
        colors_map = {
            'DDoS': '#ef4444',
            'PortScan': '#f59e0b',
            'Bot': '#8b5cf6',
            'SQL-Injection': '#dc2626',
            'XSS-Attack': '#fb923c',
            'SSH-Brute-Force': '#a855f7',
            'Slowloris-DoS': '#f472b6'
        }
        
        labels = list(attack_counts.keys())
        sizes = list(attack_counts.values())
        colors_list = [colors_map.get(label, '#64748b') for label in labels]
        
        fig, ax = plt.subplots(figsize=(10, 6), facecolor='white')
        
        # Create pie chart with better label positioning
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=None,  # We'll add labels manually
            autopct='%1.1f%%',
            startangle=90,
            colors=colors_list,
            explode=[0.05] * len(labels),  # Slight separation
            textprops={'fontsize': 11, 'weight': 'bold', 'color': 'white'}
        )
        
        # Add legend instead of labels on pie
        ax.legend(
            wedges,
            [f'{label} ({count})' for label, count in attack_counts.items()],
            title="Attack Types",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1),
            fontsize=10,
            frameon=True,
            shadow=True
        )
        
        ax.set_title('Attack Distribution', fontsize=16, fontweight='bold', pad=20)
        
        # Save to buffer
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_timeline_chart(self):
        """Create attack timeline chart"""
        if not self.alerts:
            return None
        
        # Group by hour
        hours = {}
        for alert in self.alerts:
            ts = datetime.fromisoformat(alert['timestamp'])
            hour_key = ts.strftime('%H:00')
            hours[hour_key] = hours.get(hour_key, 0) + 1
        
        # Sort by hour
        sorted_hours = sorted(hours.items())
        hour_labels = [h[0] for h in sorted_hours]
        counts = [h[1] for h in sorted_hours]
        
        fig, ax = plt.subplots(figsize=(10, 4), facecolor='white')
        
        bars = ax.bar(range(len(hour_labels)), counts, color='#3b82f6', alpha=0.8, edgecolor='#1e40af', linewidth=1.5)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        ax.set_xlabel('Hour', fontsize=11, fontweight='bold')
        ax.set_ylabel('Attack Count', fontsize=11, fontweight='bold')
        ax.set_title('Attack Timeline (Hourly Distribution)', fontsize=14, fontweight='bold', pad=15)
        ax.set_xticks(range(len(hour_labels)))
        ax.set_xticklabels(hour_labels, rotation=45, ha='right')
        ax.grid(axis='y', alpha=0.3, linestyle='--')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_severity_chart(self):
        """Create threat severity distribution chart"""
        if not self.alerts:
            return None
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for alert in self.alerts:
            conf = alert['confidence']
            if conf >= 95:
                severity_counts['CRITICAL'] += 1
            elif conf >= 85:
                severity_counts['HIGH'] += 1
            elif conf >= 75:
                severity_counts['MEDIUM'] += 1
            else:
                severity_counts['LOW'] += 1
        
        # Filter out zero counts
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if not severity_counts:
            return None
        
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        colors_list = {'CRITICAL': '#dc2626', 'HIGH': '#ef4444', 'MEDIUM': '#f59e0b', 'LOW': '#22c55e'}
        chart_colors = [colors_list[label] for label in labels]
        
        fig, ax = plt.subplots(figsize=(8, 5), facecolor='white')
        
        bars = ax.barh(labels, sizes, color=chart_colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        
        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f' {int(width)} ({int(width/sum(sizes)*100)}%)',
                   ha='left', va='center', fontsize=10, fontweight='bold')
        
        ax.set_xlabel('Number of Alerts', fontsize=11, fontweight='bold')
        ax.set_title('Threat Severity Distribution', fontsize=14, fontweight='bold', pad=15)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        buf.seek(0)
        plt.close()
        
        return buf
    
    def generate_report(self):
        """Generate comprehensive PDF report"""
        
        # Create PDF
        doc = SimpleDocTemplate(
            str(self.filepath),
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        # Header
        elements.append(Paragraph("🛡️ AI-IDS PROFESSIONAL", title_style))
        elements.append(Paragraph("Intrusion Detection System - Security Report", subtitle_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Report Info Box
        report_info = [
            ['Report Generated:', datetime.now().strftime('%B %d, %Y at %H:%M:%S')],
            ['Total Alerts:', f"{len(self.alerts):,}"],
            ['Reporting Period:', f"Last {len(self.alerts)} detected threats"],
            ['System Status:', '🟢 Active & Monitoring']
        ]
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#475569')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e293b')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.4*inch))
        
        # Executive Summary
        elements.append(Paragraph("📊 Executive Summary", heading_style))
        
        attack_counts = Counter(a['label'] for a in self.alerts)
        top_attack = attack_counts.most_common(1)[0] if attack_counts else ('None', 0)
        
        critical_count = sum(1 for a in self.alerts if a['confidence'] >= 95)
        
        summary_text = f"""
        <b>Primary Threat:</b> {top_attack[0]} ({top_attack[1]} incidents)<br/>
        <b>Critical Alerts:</b> {critical_count} (requiring immediate attention)<br/>
        <b>Attack Types Detected:</b> {len(attack_counts)} different vectors<br/>
        <b>Average Confidence:</b> {sum(a['confidence'] for a in self.alerts) / len(self.alerts):.1f}% (High accuracy)
        """
        
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Attack Distribution Chart
        elements.append(Paragraph("📈 Attack Distribution Analysis", heading_style))
        chart_buf = self.create_attack_distribution_chart()
        if chart_buf:
            chart_img = Image(chart_buf, width=5.5*inch, height=3.3*inch)
            elements.append(chart_img)
            elements.append(Spacer(1, 0.3*inch))
        
        # Timeline Chart
        elements.append(Paragraph("⏱️ Attack Timeline", heading_style))
        timeline_buf = self.create_timeline_chart()
        if timeline_buf:
            timeline_img = Image(timeline_buf, width=6*inch, height=2.4*inch)
            elements.append(timeline_img)
            elements.append(Spacer(1, 0.3*inch))
        
        # Page Break
        elements.append(PageBreak())
        
        # Severity Distribution
        elements.append(Paragraph("🚨 Threat Severity Analysis", heading_style))
        severity_buf = self.create_severity_chart()
        if severity_buf:
            severity_img = Image(severity_buf, width=5*inch, height=3*inch)
            elements.append(severity_img)
            elements.append(Spacer(1, 0.3*inch))
        
        # Detailed Alerts Table
        elements.append(Paragraph("📋 Detailed Alert Log (Latest 20)", heading_style))
        
        table_data = [['Time', 'Attack Type', 'Confidence', 'Port', 'Packets']]
        
        for alert in self.alerts[-20:]:
            ts = datetime.fromisoformat(alert['timestamp']).strftime('%H:%M:%S')
            table_data.append([
                ts,
                alert['label'],
                f"{alert['confidence']}%",
                str(alert.get('dst_port', 'N/A')),
                str(alert['fwd_pkts'] + alert['bwd_pkts'])
            ])
        
        alert_table = Table(table_data, colWidths=[1*inch, 2*inch, 1*inch, 0.8*inch, 1*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        
        elements.append(alert_table)
        elements.append(Spacer(1, 0.4*inch))
        
        # Footer
        footer_text = f"""
        <para alignment='center'>
        <b>AI-IDS Professional</b> | Developed by Aashish Chaudhari<br/>
        Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <font color='#64748b' size=8>This report contains confidential security information</font>
        </para>
        """
        elements.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        
        return self.filename


if __name__ == "__main__":
    # Test with sample data
    sample_alerts = [
        {'label': 'DDoS', 'confidence': 98, 'timestamp': '2026-02-26T10:00:00', 'dst_port': 80, 'fwd_pkts': 100, 'bwd_pkts': 50},
        {'label': 'PortScan', 'confidence': 95, 'timestamp': '2026-02-26T11:00:00', 'dst_port': 22, 'fwd_pkts': 10, 'bwd_pkts': 5},
    ]
    
    generator = IDSReportGenerator(sample_alerts)
    filename = generator.generate_report()
    print(f"Report generated: {filename}")
