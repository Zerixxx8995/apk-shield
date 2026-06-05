import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import time
import json
import os

from analyzer.apk_parser import parse_apk
from analyzer.permission_analyzer import analyze_permissions
from analyzer.api_call_analyzer import analyze_api_calls
from analyzer.component_analyzer import analyze_components
from analyzer.string_analyzer import analyze_strings
from analyzer.tracker_detector import detect_trackers
from analyzer.opcode_analyzer import analyze_opcodes
from analyzer.risk_scorer import calculate_risk
from utils.file_handler import save_uploaded_file, delete_file
from utils.report_exporter import export_json, export_pdf

# Set page config
st.set_page_config(page_title="APK Shield", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS FOR DARK CYBERSECURITY THEME ---
st.markdown("""
<style>
    .reportview-container { background: #0D1117; }
    .sidebar .sidebar-content { background: #161b22; }
    h1, h2, h3, h4, h5, span, p { color: #c9d1d9; }
    .badge-critical { background-color: #FF4B4B; color: white; padding: 5px 10px; border-radius: 15px; font-weight: bold; }
    .badge-high { background-color: #FFA500; color: white; padding: 5px 10px; border-radius: 15px; font-weight: bold; }
    .badge-medium { background-color: #FFD700; color: black; padding: 5px 10px; border-radius: 15px; font-weight: bold; }
    .badge-low { background-color: #00FF88; color: black; padding: 5px 10px; border-radius: 15px; font-weight: bold; }
    .stProgress > div > div > div > div { background-color: #00FF88; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://img.icons8.com/nolan/256/shield.png", width=80)
    st.title("🛡️ APK Shield settings")
    st.markdown("Android Malware Risk Analyzer")
    
    st.header("Analysis Settings")
    enable_ml = st.checkbox("Enable ML Scoring", value=True)
    check_headers = st.checkbox("Check Domain Headers (slower)", value=False)
    enable_deep_opcode = st.checkbox("Deep Opcode Analysis", value=False, help="May cause performance issues on large APKs")
    
    st.markdown("---")
    st.markdown("**About**\nA cybersecurity tool for deep static analysis of Android APK files.")
    st.markdown("[GitHub Repository](#)")
    
    run_demo = st.button("Run Demo Analysis", use_container_width=True)

# --- HEADER ---
st.title("🛡️ APK Shield")
st.subheader("Android Malware Risk Analyzer")
st.markdown("---")

def get_demo_results():
    time.sleep(1)
    return {
        "basics": {"app_name": "DemoApp", "package_name": "com.evil.demo", "version_name": "1.0", "version_code": "1", "min_sdk": "21", "target_sdk": "33", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "malware_match": True},
        "permissions": {"permissions": [{"name": "android.permission.SEND_SMS", "category": "DANGEROUS", "weight": 9.0}, {"name": "android.permission.INTERNET", "category": "NORMAL", "weight": 0}], "score": 9.0, "rate": 0.5, "total": 2},
        "apis": {"apis": [{"method": "sendTextMessage", "class": "android/telephony/SmsManager", "risk_level": "HIGH", "points": 10}], "score": 10},
        "components": {"patterns": [{"tag": "SMS Hijacking pattern", "desc": "Listens for SMS and has permission to Send SMS", "severity": "CRITICAL"}], "score": 25},
        "strings": {"urls": [{"url": "http://evil-c2.com/api", "type": "External", "headers": "Missing: XSS, HSTS"}], "ips": ["192.168.1.100"], "secrets": [], "score": 0},
        "trackers": {"trackers": [{"name": "Firebase", "category": "Analytics", "risk_level": "LOW"}], "score": 2},
        "opcodes": {"obfuscation_risk": True, "score": 15, "indicators": {"invoke-runtime": 50}, "total_instructions": 500},
        "risk": {"final_score": 85, "risk_label": "CRITICAL", "ml_used": False, "confidence": "ML model not loaded - using heuristic scoring only.", "breakdown": {"permissions": 9, "api_calls": 10, "components": 25, "strings_secrets": 0, "trackers": 2, "opcode": 15}}
    }

def analyze_uploaded_apk(file_path):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    status_text.text("[✓] Parsing APK structure...")
    apk_obj, dvm_array, analysis_obj, basics = parse_apk(file_path)
    if "error" in basics:
        st.error(f"Failed to parse APK: {basics['error']}")
        return None
    progress_bar.progress(15)
    
    # Check Malware Hash
    basics["malware_match"] = False
    try:
        with open('data/known_malware_hashes.json', 'r') as f:
            known = json.load(f)
            if basics["sha256"] in known:
                basics["malware_match"] = True
    except:
        pass
    
    status_text.text("[✓] Extracting permissions...")
    perm_data = analyze_permissions(apk_obj, dvm_array)
    progress_bar.progress(30)
    
    status_text.text("[✓] Scanning API calls...")
    api_data = analyze_api_calls(analysis_obj)
    progress_bar.progress(45)
    
    status_text.text("[✓] Analyzing components...")
    comp_data = analyze_components(apk_obj)
    progress_bar.progress(60)
    
    status_text.text("[✓] Scanning strings & secrets...")
    str_data = analyze_strings(dvm_array, apk_obj, check_headers)
    progress_bar.progress(75)
    
    status_text.text("[✓] Detecting trackers...")
    trk_data = detect_trackers(dvm_array)
    progress_bar.progress(85)
    
    status_text.text("[✓] Calculating risk score...")
    opc_data = analyze_opcodes(analysis_obj, enable_deep_opcode)
    risk_data = calculate_risk(perm_data, api_data, comp_data, str_data, trk_data, opc_data, apk_obj, analysis_obj)
    progress_bar.progress(100)
    
    time.sleep(0.5)
    status_text.empty()
    progress_bar.empty()
    
    return {
        "basics": basics,
        "permissions": perm_data,
        "apis": api_data,
        "components": comp_data,
        "strings": str_data,
        "trackers": trk_data,
        "opcodes": opc_data,
        "risk": risk_data
    }

results = None

uploaded_file = st.file_uploader("Upload an APK file", type=['apk'])

if run_demo:
    st.info("⚠️ RUNNING DEMO MODE (SIMULATED DATA)")
    results = get_demo_results()
elif uploaded_file is not None:
    file_path = save_uploaded_file(uploaded_file)
    if file_path:
        with st.spinner("Analyzing APK... This may take a minute."):
            results = analyze_uploaded_apk(file_path)
        delete_file(file_path)

if results:
    if not results["risk"]["ml_used"]:
        st.warning(f"🤖 {results['risk']['confidence']}")
        
    if results["basics"].get("malware_match"):
         st.error("🚨 CRITICAL ALERT: The SHA256 hash of this APK matches a known malware sample in our database!")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 OVERVIEW DASHBOARD", 
        "🔐 PERMISSIONS", 
        "⚠️ SUSPICIOUS APIs & COMPONENTS", 
        "🌐 NETWORK & SECRETS", 
        "📦 TRACKERS & AD LIBRARIES", 
        "📄 FULL REPORT"
    ])
    
    with tab1:
        c1, c2 = st.columns([1, 2])
        
        with c1:
            st.markdown("### App Information")
            st.write(f"**Name:** {results['basics']['app_name']}")
            st.write(f"**Package:** {results['basics']['package_name']}")
            st.write(f"**Version:** {results['basics']['version_name']} ({results['basics']['version_code']})")
            st.write(f"**SDK:** Min {results['basics']['min_sdk']} / Target {results['basics']['target_sdk']}")
            st.write(f"**SHA256:** `{results['basics']['sha256'][:15]}...`")
            
        with c2:
            score = results['risk']['final_score']
            color = "green" if score <=25 else "yellow" if score <=50 else "orange" if score <=75 else "red"
            
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Malware Risk Score", 'font': {'color': 'white'}},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': color},
                    'steps' : [
                        {'range': [0, 25], 'color': "rgba(0, 255, 136, 0.2)"},
                        {'range': [25, 50], 'color': "rgba(255, 215, 0, 0.2)"},
                        {'range': [50, 75], 'color': "rgba(255, 165, 0, 0.2)"},
                        {'range': [75, 100], 'color': "rgba(255, 75, 75, 0.2)"}
                    ],
                }
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': 'white'})
            st.plotly_chart(fig, use_container_width=True)
            
            badge_class = f"badge-{results['risk']['risk_label'].lower().replace(' ', '-')}"
            st.markdown(f"<div style='text-align: center;'><span class='{badge_class}'>{results['risk']['risk_label']}</span></div>", unsafe_allow_html=True)
            
        st.markdown("---")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Dangerous Permissions", sum(1 for p in results['permissions']['permissions'] if p['category'] == 'DANGEROUS'))
        m2.metric("Suspicious APIs", len(results['apis']['apis']))
        m3.metric("Trackers Found", len(results['trackers']['trackers']))
        m4.metric("Secrets Detected", len(results['strings']['secrets']))
        
        st.markdown("### Top Risk Factors")
        breakdown = results['risk']['breakdown']
        df_breakdown = pd.DataFrame(list(breakdown.items()), columns=['Module', 'Risk Points'])
        df_breakdown = df_breakdown.sort_values(by='Risk Points', ascending=False)
        fig_bar = px.bar(df_breakdown, x='Risk Points', y='Module', orientation='h', title="Risk Contribution by Module", template="plotly_dark")
        st.plotly_chart(fig_bar, use_container_width=True)
        
        if results['components']['patterns']:
            st.markdown("### Behavioral Tags")
            tags = " ".join([f"<span class='badge-critical'>{p['tag']}</span>" for p in results['components']['patterns']])
            st.markdown(tags, unsafe_allow_html=True)
            
    with tab2:
        st.markdown("### 🔐 Requested Permissions")
        if results['permissions']['permissions']:
            df_perms = pd.DataFrame(results['permissions']['permissions'])
            
            def color_perms(val):
                if val == 'DANGEROUS': return 'color: red;'
                elif val == 'SUSPICIOUS': return 'color: orange;'
                else: return 'color: green;'
            
            st.dataframe(df_perms.style.map(color_perms, subset=['category']), use_container_width=True)
        else:
            st.info("No permissions found.")
            
        st.metric("Permission Rate (Permissions / Dex Classes)", round(results['permissions']['rate'], 4))

    with tab3:
        st.markdown("### ⚠️ Suspicious API Calls")
        if results['apis']['apis']:
            df_apis = pd.DataFrame(results['apis']['apis'])
            st.dataframe(df_apis, use_container_width=True)
        else:
            st.info("No suspicious APIs detected.")
            
        st.markdown("---")
        st.markdown("### 🧩 Behavioral Patterns Detected")
        if results['components']['patterns']:
            for p in results['components']['patterns']:
                with st.expander(f"🛑 {p['tag']} ({p['severity']})"):
                    st.write(p['desc'])
        else:
            st.info("No strong behavioral red flags detected.")
            
        st.markdown("---")
        st.markdown("### 🧬 Opcode Obfuscation Analysis")
        if enable_deep_opcode or run_demo:
            st.write(f"Total Instructions Scanned: {results['opcodes'].get('total_instructions', 0)}")
            is_obfuscated = results['opcodes']['obfuscation_risk']
            st.write(f"Obfuscation Risk: **{'HIGH' if is_obfuscated else 'LOW'}**")
            st.bar_chart(results['opcodes']['indicators'])
        else:
            st.info("Deep Opcode Analysis is disabled. Enable it in the sidebar.")

    with tab4:
        st.markdown("### 🌐 Network & URLs")
        if results['strings']['urls']:
            df_urls = pd.DataFrame(results['strings']['urls'])
            st.dataframe(df_urls, use_container_width=True)
        else:
            st.info("No URLs detected.")
            
        st.markdown("### 📡 IPs Found")
        if results['strings']['ips']:
            st.write(results['strings']['ips'])
        else:
            st.write("None")
            
        st.markdown("---")
        st.markdown("### 🔑 Hardcoded Secrets")
        if results['strings']['secrets']:
            df_sec = pd.DataFrame(results['strings']['secrets'])
            st.dataframe(df_sec[['type', 'redacted']], use_container_width=True)
        else:
            st.info("No standard secrets detected in strings.")

    with tab5:
        st.markdown("### 📦 Trackers & Ad Libraries")
        if results['trackers']['trackers']:
            df_trk = pd.DataFrame(results['trackers']['trackers'])
            
            # Cards
            cols = st.columns(4)
            for idx, row in df_trk.iterrows():
                col = cols[idx % 4]
                color = "red" if row['risk_level'] == 'HIGH' else "orange" if row['risk_level'] == 'MEDIUM' else "green"
                with col:
                    st.markdown(f"""
                    <div style="border: 1px solid #444; border-radius: 5px; padding: 10px; margin-bottom: 10px; text-align: center;">
                        <h4>{row['name']}</h4>
                        <p>{row['category']}</p>
                        <span style="color: {color}; font-weight: bold;">{row['risk_level']} RISK</span>
                    </div>
                    """, unsafe_allow_html=True)
            
            st.markdown("---")
            fig_pie = px.pie(df_trk, names='category', title="Trackers by Category", template="plotly_dark")
            st.plotly_chart(fig_pie)
        else:
            st.info("No known trackers detected.")
            
    with tab6:
        st.markdown("### 📄 Full Analysis Report")
        st.json(results)
        
        c1, c2 = st.columns(2)
        with c1:
            json_str = export_json(results)
            st.download_button("⬇ Download JSON Report", data=json_str, file_name="apk_shield_report.json", mime="application/json")
        with c2:
            pdf_bytes = export_pdf(results)
            st.download_button("⬇ Download PDF Report", data=pdf_bytes, file_name="apk_shield_report.pdf", mime="application/pdf")
