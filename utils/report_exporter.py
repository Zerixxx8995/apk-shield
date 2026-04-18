import json
try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

def export_json(data):
    return json.dumps(data, indent=4)

def export_pdf(data):
    if not HAS_FPDF:
        return b"%PDF-Placeholder - Please install fpdf2"
        
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 16)
    pdf.cell(0, 10, 'APK Shield - Analysis Report', new_x="LMARGIN", new_y="NEXT", align='C')
    
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, f"App Name: {data.get('basics', {}).get('app_name', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Package: {data.get('basics', {}).get('package_name', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Final Risk Score: {data.get('risk', {}).get('final_score', 0)} / 100", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Risk Label: {data.get('risk', {}).get('risk_label', 'UNKNOWN')}", new_x="LMARGIN", new_y="NEXT")
    
    return bytes(pdf.output())
