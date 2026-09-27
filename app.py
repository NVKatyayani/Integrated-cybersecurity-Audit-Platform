import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np

# 1. Scikit-learn (Machine Learning Module)
from sklearn.ensemble import IsolationForest

# 2. Scapy (Network Packet Analysis Module)
from scapy.all import IP, TCP

from database import (
    create_database, 
    save_audit, 
    get_audits, 
    clear_audits, 
    delete_audit_by_id
)

st.set_page_config(
    page_title="Integrated Cybersecurity Audit Platform",
    page_icon="🛡️",
    layout="wide"
)

create_database()

# Sidebar Navigation
with st.sidebar:
    st.title("🛡️ Cyber Audit")
    st.caption("Integrated Security Platform")
    st.divider()

    st.subheader("Navigation")
    page = st.radio(
        "Select Module",
        [
            "🏠 Dashboard",
            "🔐 Password Audit",
            "🌐 Network Audit",
            "💉 SQL Injection",
            "🎣 Phishing Audit",
            "👤 Employee Hygiene",
            "🔍 Log Analysis",
            "🗄️ Audit History"
        ]
    )

    st.divider()
    st.caption("Integrated Cybersecurity Audit Platform")
    st.caption("Academic Project Prototype")

# ---------------- DASHBOARD PAGE ----------------
if page == "🏠 Dashboard":
    st.title("🛡️ Integrated Cybersecurity Audit Platform")
    st.write("Comprehensive platform for integrated cybersecurity auditing.")
    st.success("Cybersecurity Audit Platform is running successfully!")

    st.header("📊 Security Audit Dashboard")

    audit_data = {
        "Audit Area": [
            "Password Policy",
            "Network Security",
            "SQL Injection",
            "Phishing Awareness"
        ],
        "Risk Score": [35, 55, 20, 45]
    }
    df = pd.DataFrame(audit_data)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔐 Password Audit", "35%")
    col2.metric("🌐 Network Audit", "55%")
    col3.metric("💉 SQL Injection", "20%")
    col4.metric("🎣 Phishing", "45%")

    st.divider()

    st.subheader("📈 Risk Analysis")
    fig = px.bar(
        df,
        x="Audit Area",
        y="Risk Score",
        color="Risk Score",
        color_continuous_scale="RdYlGn_r",
        title="Cybersecurity Risk by Audit Area"
    )
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    st.subheader("📋 Audit Summary")
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()

    st.header("💡 Security Recommendations")
    recommendations = [
        "🔐 Enforce strong password policies and multi-factor authentication.",
        "🌐 Monitor network traffic for suspicious activity (Scapy Powered).",
        "💉 Use parameterized queries to reduce SQL injection risk.",
        "🎣 Conduct regular phishing awareness training.",
        "👤 Improve employee cybersecurity hygiene.",
        "📋 Investigate suspicious log anomalies using Scikit-learn ML."
    ]
    for recommendation in recommendations:
        st.write(recommendation)

    st.divider()

    st.header("📊 Final Security Assessment")
    final_data = {
        "Audit Area": [
            "Password Policy",
            "Network Security",
            "SQL Injection",
            "Phishing Awareness",
            "Employee Hygiene",
            "Log Anomalies"
        ],
        "Risk Score": [35, 55, 20, 45, 50, 40]
    }
    final_df = pd.DataFrame(final_data)
    average_risk = final_df["Risk Score"].mean()

    st.metric("Overall Risk Score", f"{average_risk:.1f}%")

    if average_risk < 30:
        st.success("🟢 Overall security risk is low")
    elif average_risk < 60:
        st.warning("🟡 Overall security posture needs improvement")
    else:
        st.error("🔴 Overall security risk is high")

# ---------------- PASSWORD AUDIT PAGE ----------------
elif page == "🔐 Password Audit":
    st.header("🔐 Password Policy Audit")

    password = st.text_input(
        "Enter a test password",
        type="password",
        placeholder="Enter password for security analysis"
    )

    if password:
        score = 0
        checks = []

        if len(password) >= 8:
            score += 20
            checks.append(("Minimum 8 characters", True))
        else:
            checks.append(("Minimum 8 characters", False))

        if any(c.isupper() for c in password):
            score += 20
            checks.append(("Uppercase letter", True))
        else:
            checks.append(("Uppercase letter", False))

        if any(c.islower() for c in password):
            score += 20
            checks.append(("Lowercase letter", True))
        else:
            checks.append(("Lowercase letter", False))

        if any(c.isdigit() for c in password):
            score += 20
            checks.append(("Number", True))
        else:
            checks.append(("Number", False))

        if any(not c.isalnum() for c in password):
            score += 20
            checks.append(("Special character", True))
        else:
            checks.append(("Special character", False))

        st.metric("Password Security Score", f"{score}/100")
        st.progress(score / 100)

        for check, passed in checks:
            if passed:
                st.success("✅ " + check)
            else:
                st.error("❌ " + check)

        if score >= 80:
            status = "Strong"
            st.success("Strong password")
        elif score >= 60:
            status = "Moderate"
            st.warning("Moderate password — improvement recommended")
        else:
            status = "Weak"
            st.error("Weak password — security improvement required")

        if st.button("💾 Save Password Audit"):
            risk_score = 100 - score
            save_audit("Password Policy", risk_score, status)
            st.success("✅ Password audit result saved successfully!")

# ---------------- NETWORK AUDIT PAGE (SCAPY POWERED) ----------------
elif page == "🌐 Network Audit":
    st.header("🌐 Network Security Audit (Scapy Engine)")
    st.write("Analyze network packets and security configurations.")

    firewall = st.checkbox("Firewall is enabled")
    antivirus = st.checkbox("Antivirus is active")
    monitoring = st.checkbox("Network traffic is monitored")
    updates = st.checkbox("Network devices are updated")

    st.subheader("📡 Live Scapy Packet Inspection")
    if st.button("Run Packet Audit with Scapy"):
        # Constructing synthetic packet using Scapy
        pkt = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
        
        st.info(f"**Scapy Packet Summary:** `{pkt.summary()}`")
        st.code(f"Source IP: {pkt[IP].src}\nDestination IP: {pkt[IP].dst}\nProtocol: TCP Port {pkt[TCP].dport}")

        score = 0
        if firewall: score += 25
        if antivirus: score += 25
        if monitoring: score += 25
        if updates: score += 25

        risk_score = 100 - score

        st.metric("Network Security Score", f"{score}%")
        st.progress(score / 100)

        if score >= 75:
            status = "Good"
            st.success("✅ Network security controls are good")
        elif score >= 50:
            status = "Moderate"
            st.warning("⚠️ Network security needs improvement")
        else:
            status = "High Risk"
            st.error("🚨 Network security risk is high")

        if st.button("💾 Save Network Audit"):
            save_audit("Network Security", risk_score, status)
            st.success("✅ Network audit result saved!")

# ---------------- SQL INJECTION PAGE ----------------
elif page == "💉 SQL Injection":
    st.header("💉 SQL Injection Risk Checker")

    sql_input = st.text_area(
        "Enter a test SQL query or input",
        placeholder="Example: SELECT * FROM users WHERE username='admin'"
    )

    if sql_input:
        sql_text = sql_input.lower()
        suspicious_patterns = [
            "' or '1'='1", "' or 1=1", "or 1=1", "union select",
            "drop table", "--", "/*", "*/", "xp_cmdshell"
        ]

        detected = [p for p in suspicious_patterns if p in sql_text]
        risk_score = min(len(detected) * 25, 100)

        if detected:
            st.error("🚨 Potential SQL Injection Pattern Detected")
            st.write("Suspicious patterns found:")
            for pattern in detected:
                st.warning(pattern)
            st.info("Recommendation: Use parameterized queries, input validation, and prepared statements.")
        else:
            st.success("✅ No common SQL injection patterns detected")

        if risk_score >= 75: status = "High Risk"
        elif risk_score >= 50: status = "Medium Risk"
        elif risk_score > 0: status = "Low Risk"
        else: status = "Safe"

        st.metric("SQL Injection Risk Score", f"{risk_score}/100")

        if st.button("💾 Save SQL Injection Audit"):
            save_audit("SQL Injection", risk_score, status)
            st.success("✅ SQL Injection audit result saved!")

# ---------------- PHISHING AUDIT PAGE ----------------
elif page == "🎣 Phishing Audit":
    st.header("🎣 Phishing Awareness Analyzer")

    message = st.text_area(
        "Paste a test email or message",
        placeholder="Example: Your account will be blocked. Click here immediately to verify your password."
    )

    if message:
        text = message.lower()
        phishing_patterns = [
            "urgent", "verify your account", "account will be blocked",
            "click here", "reset your password", "claim your prize",
            "you have won", "suspended", "confirm your account", "limited time"
        ]

        detected = [p for p in phishing_patterns if p in text]
        risk_score = min(len(detected) * 15, 100)

        st.metric("Phishing Risk Score", f"{risk_score}/100")
        st.progress(risk_score / 100)

        if risk_score >= 60:
            status = "High Risk"
            st.error("🚨 High phishing risk detected")
        elif risk_score >= 30:
            status = "Medium Risk"
            st.warning("⚠️ Medium phishing risk detected")
        else:
            status = "Low Risk"
            st.success("✅ Low phishing risk detected")

        if detected:
            st.write("Suspicious indicators found:")
            for item in detected:
                st.warning("⚠️ " + item)

        if st.button("💾 Save Phishing Audit"):
            save_audit("Phishing Awareness", risk_score, status)
            st.success("✅ Phishing audit result saved!")

# ---------------- EMPLOYEE HYGIENE PAGE ----------------
elif page == "👤 Employee Hygiene":
    st.header("👤 Employee Cybersecurity Hygiene")
    st.write("Check basic employee security practices.")

    password_change = st.checkbox("I change my passwords regularly")
    mfa = st.checkbox("I use Multi-Factor Authentication")
    updates = st.checkbox("I keep software updated")
    phishing_training = st.checkbox("I complete phishing awareness training")

    if st.button("Calculate Hygiene Score"):
        score = 0
        if password_change: score += 25
        if mfa: score += 25
        if updates: score += 25
        if phishing_training: score += 25

        risk_score = 100 - score

        st.metric("Employee Hygiene Score", f"{score}%")
        st.progress(score / 100)

        if score >= 75:
            status = "Good"
            st.success("✅ Good cybersecurity hygiene")
        elif score >= 50:
            status = "Moderate"
            st.warning("⚠️ Moderate cybersecurity hygiene")
        else:
            status = "Needs Improvement"
            st.error("🚨 Cybersecurity hygiene needs improvement")

        if st.button("💾 Save Hygiene Audit"):
            save_audit("Employee Hygiene", risk_score, status)
            st.success("✅ Employee hygiene audit saved!")

# ---------------- LOG ANALYSIS PAGE (SCIKIT-LEARN INTEGRATED) ----------------
elif page == "🔍 Log Analysis":
    st.header("🔍 Log Anomaly Detection (Scikit-Learn ML)")
    st.write("Machine Learning Isolation Forest algorithm for detecting abnormal log activities.")

    log_message = st.text_area(
        "Log Message",
        placeholder="Example: Multiple failed login attempts from unknown IP"
    )

    if st.button("Analyze Log with Scikit-Learn ML"):
        if not log_message.strip():
            st.warning("⚠️ Please enter a log message first.")
        else:
            # Feature extraction
            length = len(log_message)
            num_uppercase = sum(1 for c in log_message if c.isupper())
            num_special = sum(1 for c in log_message if not c.isalnum() and not c.isspace())

            # Dataset for Scikit-learn ML Training
            X_train = np.array([
                [20, 1, 2], [25, 2, 3], [30, 0, 1], [15, 0, 0],  # Normal logs
                [150, 45, 20], [200, 60, 35], [180, 50, 30]     # Anomalous logs
            ])

            # Scikit-Learn Model Setup
            model = IsolationForest(contamination=0.2, random_state=42)
            model.fit(X_train)

            # ML Prediction
            X_test = np.array([[length, num_uppercase, num_special]])
            prediction = model.predict(X_test)[0] # -1 = Anomaly, 1 = Normal

            if prediction == -1:
                risk_score = 85
                status = "High Risk"
                st.error("🚨 Scikit-Learn IsolationForest Model Flagged this Log as an Anomaly! (-1)")
            else:
                risk_score = 20
                status = "Safe"
                st.success("✅ Scikit-Learn IsolationForest Model Classified this Log as Normal Traffic (+1)")

            st.metric("Scikit-learn Anomaly Risk Score", f"{risk_score}/100")

            if st.button("💾 Save Log Audit"):
                save_audit("Log Anomalies", risk_score, status)
                st.success("✅ Log anomaly audit saved!")

# ---------------- AUDIT HISTORY PAGE ----------------
elif page == "🗄️ Audit History":
    st.header("🗄️ Audit History")
    audit_history = get_audits()

    if audit_history:
        history_df = pd.DataFrame(
            audit_history,
            columns=["ID", "Audit Area", "Risk Score", "Status"]
        )
        st.dataframe(history_df, use_container_width=True, hide_index=True)

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🗑️ Delete Specific Record")
            audit_ids = [row[0] for row in audit_history]
            selected_id = st.selectbox("Select Record ID to delete", audit_ids)
            
            if st.button("Delete Selected Record"):
                delete_audit_by_id(selected_id)
                st.success(f"✅ Record ID {selected_id} deleted successfully!")
                st.rerun()

        with col2:
            st.subheader("⚙️ Actions")
            st.download_button(
                "⬇️ Download Audit History",
                data=history_df.to_csv(index=False),
                file_name="audit_history.csv",
                mime="text/csv"
            )
            
            if st.button("🗑️ Clear All History"):
                clear_audits()
                st.success("✅ All audit history cleared!")
                st.rerun()
    else:
        st.info("No audit results have been saved yet.")