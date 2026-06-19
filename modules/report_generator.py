import csv
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from modules import database_manager

def generate_csv_report(filepath):
    """Generates a CSV export of all recorded threats/alerts."""
    alerts = database_manager.get_all_alerts()
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Alert ID', 'Threat Type', 'IP Address', 'Risk Level', 'Status', 'Detected At'])
        
        for alert in alerts:
            writer.writerow([
                alert['id'],
                alert['threat_type'],
                alert['ip_address'],
                alert['risk_level'],
                alert['status'],
                alert['created_at']
            ])

def generate_pdf_report(filepath):
    """
    Generates a professionally formatted PDF cybersecurity report.
    Includes Executive Summary, Risk Level Breakdown, Suspicious IPs,
    and a list of the most recent alerts.
    """
    # 1. Fetch system statistics
    stats = database_manager.get_dashboard_stats()
    threat_dist = database_manager.get_threat_distribution()
    alerts = database_manager.get_all_alerts()
    
    # 2. Query distinct suspicious IPs and their alert frequencies
    conn = database_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, COUNT(*) as alert_count 
        FROM alerts 
        GROUP BY ip_address 
        ORDER BY alert_count DESC
    """)
    suspicious_ips = cursor.fetchall()
    conn.close()
    
    # 3. Setup ReportLab SimpleDocTemplate
    doc = SimpleDocTemplate(
        filepath, 
        pagesize=letter,
        rightMargin=40, 
        leftMargin=40, 
        topMargin=40, 
        bottomMargin=40
    )
    story = []
    
    # 4. Define Document Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'), # Deep Navy
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )
    
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155')
    )
    
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=12,
        textColor=colors.HexColor('#1E293B')
    )

    # 5. Header / Cover Block
    story.append(Paragraph("Z+ Security &mdash; Cyber Threat Analysis Report", title_style))
    story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: Security Watch Database", subtitle_style))
    story.append(Spacer(1, 10))
    
    # 6. Executive Summary Section
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(
        "This diagnostic report outlines security events, access logs, and malicious threats identified by the Z+ Security monitoring system. "
        "The metrics below summarize raw logs analyzed and threats parsed during operational cycles.",
        body_style
    ))
    story.append(Spacer(1, 10))
    
    # Summary Table
    summary_data = [
        [Paragraph("Metric Indicator", table_header_style), Paragraph("Total Quantity", table_header_style)],
        [Paragraph("Total Logs Analyzed", body_style), Paragraph(str(stats['total_logs']), body_style)],
        [Paragraph("Total Threats Detected", body_style), Paragraph(str(stats['total_threats']), body_style)],
        [Paragraph("High Risk Threats", body_style), Paragraph(str(stats['high_risk_threats']), body_style)],
        [Paragraph("Safe/Operational Logs", body_style), Paragraph(str(stats['safe_events']), body_style)]
    ]
    t_summary = Table(summary_data, colWidths=[280, 180])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')])
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))
    
    # 7. Threat Classification breakdown
    story.append(Paragraph("2. Threat Classification Breakdown", h2_style))
    breakdown_data = [
        [Paragraph("Risk Level Class", table_header_style), Paragraph("Alert Count / Events", table_header_style)],
        [Paragraph("<font color='#10B981'><b>Safe / Normal Action</b></font>", body_style), Paragraph(str(threat_dist.get('Safe', 0)), body_style)],
        [Paragraph("<font color='#3B82F6'><b>Low Threat Level</b></font>", body_style), Paragraph(str(threat_dist.get('Low', 0)), body_style)],
        [Paragraph("<font color='#F59E0B'><b>Medium Threat Level</b></font>", body_style), Paragraph(str(threat_dist.get('Medium', 0)), body_style)],
        [Paragraph("<font color='#EF4444'><b>High Threat Level</b></font>", body_style), Paragraph(str(threat_dist.get('High', 0)), body_style)]
    ]
    t_breakdown = Table(breakdown_data, colWidths=[280, 180])
    t_breakdown.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')])
    ]))
    story.append(t_breakdown)
    story.append(Spacer(1, 15))
    
    # 8. Suspicious IPs List
    story.append(Paragraph("3. Flagged Suspicious IP Addresses", h2_style))
    story.append(Paragraph(
        "Below are IP addresses contributing to warnings, login failures, or identified outside the designated IP whitelist.",
        body_style
    ))
    story.append(Spacer(1, 10))
    
    if suspicious_ips:
        ip_data = [[Paragraph("IP Address Source", table_header_style), Paragraph("Alert Frequency", table_header_style)]]
        for row in suspicious_ips[:15]: # Show top 15 suspicious IPs
            ip_data.append([
                Paragraph(row['ip_address'], body_style),
                Paragraph(str(row['alert_count']), body_style)
            ])
        t_ips = Table(ip_data, colWidths=[280, 180])
        t_ips.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')])
        ]))
        story.append(t_ips)
    else:
        story.append(Paragraph("No suspicious or unauthorized IP records in database history.", body_style))
    story.append(Spacer(1, 15))
    
    # 9. Recent Detailed Alerts list
    story.append(Paragraph("4. Recent Incident Log Records", h2_style))
    if alerts:
        alerts_data = [[
            Paragraph("Threat Event", table_header_style),
            Paragraph("Source IP", table_header_style),
            Paragraph("Risk", table_header_style),
            Paragraph("Status", table_header_style),
            Paragraph("Time Captured", table_header_style)
        ]]
        
        for alert in alerts[:15]: # Display the 15 most recent incidents
            risk_val = alert['risk_level']
            if risk_val == 'High':
                color_code = '#EF4444' # red
            elif risk_val == 'Medium':
                color_code = '#F59E0B' # orange
            else:
                color_code = '#3B82F6' # blue
                
            alerts_data.append([
                Paragraph(alert['threat_type'], body_style),
                Paragraph(alert['ip_address'], body_style),
                Paragraph(f"<font color='{color_code}'><b>{risk_val}</b></font>", body_style),
                Paragraph(alert['status'], body_style),
                Paragraph(alert['created_at'], body_style)
            ])
            
        t_alerts = Table(alerts_data, colWidths=[140, 85, 45, 65, 125])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')])
        ]))
        story.append(t_alerts)
    else:
        story.append(Paragraph("No incidents recorded in the security ledger.", body_style))
        
    doc.build(story)
