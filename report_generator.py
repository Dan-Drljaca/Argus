# imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os

def generate_report(filename, network_name, score, wifi_security, password_strength, ports, notes, firewall_status, remote_access_status):


    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # --- HEADER ---
    elements.append(Paragraph("<b>Argus Net Protector - Security Report</b>", styles['Title']))
    elements.append(Spacer(1, 12))

    date_str = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    elements.append(Paragraph(f"Date & Time of Scan: {date_str}", styles['Normal']))
    elements.append(Paragraph(f"Network Name (SSID): {network_name}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # --- SUMMARY SECTION ---
    elements.append(Paragraph("<b>Summary</b>", styles['Heading2']))

    summary_data = [
        ["Overall Security Score", f"{score}%"],
        ["Number of Open Ports", str(sum(1 for s in ports.values() if s.lower() == "open"))],
        ["Wi-Fi Security Type", wifi_security],
        ["Password Strength", password_strength],
        ["Firewall Status", firewall_status],
        ["Remote Access", remote_access_status],
    ]

    summary_table = Table(summary_data, hAlign="LEFT", colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # --- PORT SCAN DETAILS ---
    elements.append(Paragraph("<b>Port Scan Details</b>", styles['Heading2']))
    port_data = [["Port", "Status"]]
    for port, status in ports.items():
        port_data.append([str(port), status])

    port_table = Table(port_data, hAlign="LEFT", colWidths=[100, 100])
    port_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(port_table)
    elements.append(Spacer(1, 20))

    # --- RECOMMENDATIONS SECTION ---
    elements.append(Paragraph("<b>Recommendations</b>", styles['Heading2']))
    recommendations = notes.copy()

    # Firewall recommendations
    if firewall_status.lower() != "enabled":
        recommendations.append("Your system firewall appears to be disabled. Enable it to protect against unauthorized access.")

    # Remote Access recommendations
    if remote_access_status.lower() == "enabled":
        recommendations.append("Remote access is enabled. Disable it when not needed to reduce potential security risks.")



    if recommendations:
        for note in recommendations:
            elements.append(Paragraph(f"- {note}", styles['Normal']))
    else:
        elements.append(Paragraph("No recommendations at this time.", styles['Normal']))

    elements.append(Spacer(1, 20))

    # --- FOOTER DISCLAIMER ---
    elements.append(Paragraph(
        "<b>Disclaimer:</b> This application is intended to help users improve their network security. "
        "It provides recommendations based on detected issues but is not responsible for any outcomes "
        "or damages resulting from its use.",
        styles['Normal']
    ))

    # --- BUILD PDF ---
    doc.build(elements)
    print(f"Report generated: {os.path.abspath(filename)}")



# Debugging section
if __name__ == "__main__":
    test_ports = {22: "closed", 23: "open", 80: "closed"}
    test_notes = [
        "Port 23 is open. Consider closing it.",
        "Wi-Fi password could be stronger."
    ]

    generate_report(
        filename="test_report.pdf",
        network_name="TestWiFi",
        score=75,
        wifi_security="WPA2",
        password_strength="65%",
        ports=test_ports,
        notes=test_notes,
        firewall_status="Enabled",
        remote_access_status="Disabled"
    )
