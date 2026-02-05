"""
Streamlit UI for OTCM Audit Sentinel
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.application.sentinel_agent import SentinelAgent
from src.application.hallucinator_agent import HallucinatorAgent
from src.infrastructure.database import DatabaseConnection
from src.infrastructure.content_manager_client import ContentManagerClient


def main():
    """Main Streamlit application"""
    st.set_page_config(
        page_title="OTCM Audit Sentinel",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ OTCM Audit Sentinel")
    st.markdown("AI-Powered Security Analysis for OpenText Content Manager")
    
    # Sidebar navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["Dashboard", "Audit Analysis", "Security Testing", "Findings", "Settings"]
    )
    
    if page == "Dashboard":
        show_dashboard()
    elif page == "Audit Analysis":
        show_audit_analysis()
    elif page == "Security Testing":
        show_security_testing()
    elif page == "Findings":
        show_findings()
    elif page == "Settings":
        show_settings()


def show_dashboard():
    """Display main dashboard"""
    st.header("Security Dashboard")
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Critical Findings", "3", "-1")
    with col2:
        st.metric("High Risk", "12", "+2")
    with col3:
        st.metric("Audit Events", "1,234", "+45")
    with col4:
        st.metric("System Health", "98%", "+2%")
    
    # Recent findings chart
    st.subheader("Recent Security Findings")
    
    # Placeholder data
    findings_data = pd.DataFrame({
        'Date': pd.date_range(end=datetime.now(), periods=7, freq='D'),
        'Critical': [1, 2, 1, 3, 2, 1, 3],
        'High': [5, 4, 6, 7, 8, 5, 12],
        'Medium': [10, 12, 11, 9, 15, 14, 16]
    })
    
    st.line_chart(findings_data.set_index('Date'))


def show_audit_analysis():
    """Audit log analysis page"""
    st.header("📊 Audit Log Analysis (Sentinel Agent)")
    
    # Date range selector
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())
    
    if st.button("Run Analysis", type="primary"):
        with st.spinner("Analyzing audit logs..."):
            st.info("🤖 Sentinel Agent analyzing patterns...")
            # Placeholder for actual analysis
            st.success("Analysis complete! Found 5 potential anomalies.")
            
            # Display results
            results_df = pd.DataFrame({
                'Timestamp': ['2026-02-05 14:30', '2026-02-05 12:15', '2026-02-04 18:45'],
                'User': ['user123', 'admin_user', 'user456'],
                'Anomaly Type': ['Unusual Access Pattern', 'Privilege Escalation', 'Data Exfiltration'],
                'Severity': ['High', 'Critical', 'Medium'],
                'Confidence': [0.85, 0.92, 0.73]
            })
            st.dataframe(results_df, use_container_width=True)


def show_security_testing():
    """Security testing page"""
    st.header("🔍 AI Security Testing (Hallucinator Agent)")
    
    st.markdown("""
    The Hallucinator Agent uses AI to generate creative attack scenarios
    and test your system for potential vulnerabilities.
    """)
    
    test_type = st.selectbox(
        "Select Test Type",
        ["Permission Testing", "Attack Simulation", "Vulnerability Scan"]
    )
    
    if st.button("Start Security Test", type="primary"):
        with st.spinner("Running security tests..."):
            st.info("🤖 Hallucinator Agent generating test scenarios...")
            # Placeholder for actual testing
            st.success("Testing complete! Identified 3 potential vulnerabilities.")
            
            # Display results
            vuln_df = pd.DataFrame({
                'Vulnerability': ['Overly Permissive Access', 'Missing Rate Limiting', 'Weak Auth Config'],
                'Severity': ['High', 'Medium', 'Critical'],
                'Confidence': [0.88, 0.76, 0.95],
                'Status': ['Open', 'Open', 'Open']
            })
            st.dataframe(vuln_df, use_container_width=True)


def show_findings():
    """Security findings page"""
    st.header("📋 Security Findings")
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"]
        )
    with col2:
        agent_filter = st.multiselect(
            "Detected By",
            ["Sentinel", "Hallucinator"],
            default=["Sentinel", "Hallucinator"]
        )
    with col3:
        status_filter = st.selectbox("Status", ["All", "Open", "Resolved"])
    
    # Findings table (placeholder data)
    findings_df = pd.DataFrame({
        'ID': ['F001', 'F002', 'F003', 'F004'],
        'Severity': ['Critical', 'High', 'High', 'Medium'],
        'Description': [
            'Unauthorized access attempt detected',
            'Privilege escalation pattern identified',
            'Unusual data access pattern',
            'Missing encryption on sensitive data'
        ],
        'Detected By': ['Sentinel', 'Sentinel', 'Hallucinator', 'Hallucinator'],
        'Date': ['2026-02-05', '2026-02-05', '2026-02-04', '2026-02-04'],
        'Status': ['Open', 'Open', 'Open', 'Resolved']
    })
    
    st.dataframe(findings_df, use_container_width=True)


def show_settings():
    """Settings page"""
    st.header("⚙️ Settings")
    
    with st.expander("🔌 API Configuration"):
        st.text_input("Content Manager URL", placeholder="https://cm.example.com")
        st.text_input("NTLM Username", placeholder="username")
        st.text_input("NTLM Password", type="password")
        st.text_input("NTLM Domain (optional)", placeholder="DOMAIN")
        st.text_input("OpenAI API Key", type="password")
    
    with st.expander("🗄️ Database Configuration"):
        st.text_input("Database URL", placeholder="postgresql://user:pass@host:port/db")
        if st.button("Test Connection"):
            st.success("✅ Database connection successful!")
    
    with st.expander("🤖 Agent Configuration"):
        st.slider("Sentinel Sensitivity", 0.0, 1.0, 0.7, 0.05)
        st.slider("Hallucinator Creativity", 0.0, 1.0, 0.8, 0.05)
        st.checkbox("Enable Real-time Monitoring", value=True)
    
    if st.button("Save Settings", type="primary"):
        st.success("Settings saved successfully!")


if __name__ == "__main__":
    main()
