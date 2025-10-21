# imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os

def generate_report(filename, network_name, score, wifi_security, password_strength, ports, notes):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    #header
    elements.append(Paragraph("<b>Argus Net Protector - Security Report</b>", styles['Title']))
    elements.append(Spacer(1,12))
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #might change from y-m-d ot m-d-y 
    elements.append(Paragraph(f"Date & Time of Scan: {date_str}", styles['Normal']))
    elements.append(Paragraph(f"Network Name (SSID): {network_name}", styles['Normal']))
    elements.append(Spacer(1,12))
    
    #section one summary
    elements.append(Paragraph("<b>Summary</b>", styles['Heading2']))
    summary_data =[
        ["Overall Security Score", f"{score}%"],
        ["Number of Open Ports", str(sum(1 for s in ports.values() if s.lower() == "open"))],
        ["Wi-Fi Security Type", wifi_security],
        ["Password Strength", password_strength],

    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1,20))

    #section two port details 
    elements.append(Paragraph("<b> Port Scan Details</b>", styles['Heading2']))
    port_data = [["Port","Status"]]
    for port, status in ports.items():
        port_data.append([str(port), status])
   
    port_table = Table(port_data, hAlign="LEFT")
    port_table_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
    ])
    port_table.setStyle(port_table_style)
    elements.append(port_table)
    elements.append(Spacer(1, 20))

    #section three reccomndations
    elements.append(Paragraph("<b>Recommendations</b>", styles['Heading2']))
    if notes:
        for note in notes:
            elements.append(Paragraph(f"- {note}", styles['Normal']))
    else:
        elements.append(Paragraph("No recommendations at this time.", styles['Normal']))
    elements.append(Spacer(1, 20))

    #footer disclaimer 
    elements.append(Paragraph(
        "<b>Disclaimer:</b> This application is intended to help users improve their network security. "
        "It provides recommendations based on detected issues but is not responsible for any outcomes "
        "or damages resulting from its use.",
        styles['Normal']
    ))

    # Build the PDF
    doc.build(elements)
    print(f" Report generated: {os.path.abspath(filename)}")

#debugging 
if __name__ == "__main__":
    test_ports = {22: "closed", 23: "open", 80: "closed"}
    test_notes = [
        "Port 23 is open. Consider closing it.",
        "Wi-Fi password could be stronger."
    ]

    generate_report(
        filename="test_report.pdf",
        network_name="TestWiFi",
        score=70,
        wifi_security="WPA2",
        password_strength="Strong",
        ports=test_ports,
        notes=test_notes
    )

