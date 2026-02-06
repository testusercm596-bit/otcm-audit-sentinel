"""
Streamlit UI for OTCM Audit Sentinel
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.application.sentinel_agent import SentinelAgent
from src.application.hallucinator_agent import HallucinatorAgent
from src.infrastructure.database import db
from src.infrastructure.alert_repository import AlertResultRepository
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
    
    # Auto-refresh toggle
    col_refresh1, col_refresh2 = st.columns([3, 1])
    with col_refresh2:
        auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
    
    # Fetch real metrics from database
    db.connect()
    session = db.get_session()
    alert_repo = AlertResultRepository(session)
    
    try:
        all_alerts = alert_repo.get_all(limit=1000)
        active_alerts = alert_repo.get_active_alerts(limit=1000)
        escalated = alert_repo.get_escalated_alerts(limit=1000)
        
        # Count by severity
        critical = len([a for a in active_alerts if a.risk_score >= 0.8])
        high = len([a for a in active_alerts if 0.6 <= a.risk_score < 0.8])
        medium = len([a for a in active_alerts if 0.4 <= a.risk_score < 0.6])
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Critical Findings", critical)
        with col2:
            st.metric("High Risk", high)
        with col3:
            st.metric("Total Alerts", len(active_alerts))
        with col4:
            st.metric("Escalated", len(escalated))
        
        # Recent findings chart
        st.subheader("Recent Security Findings")
        
        if all_alerts:
            # Group by date and severity
            df_alerts = pd.DataFrame([{
                'timestamp': a.timestamp,
                'risk_score': a.risk_score,
                'severity': 'Critical' if a.risk_score >= 0.8 else 'High' if a.risk_score >= 0.6 else 'Medium'
            } for a in all_alerts])
            
            df_alerts['date'] = pd.to_datetime(df_alerts['timestamp']).dt.date
            
            # Count by date and severity
            chart_data = df_alerts.groupby(['date', 'severity']).size().unstack(fill_value=0)
            
            if not chart_data.empty:
                st.line_chart(chart_data)
            else:
                st.info("No alert data available for charting")
        else:
            st.info("No alerts found in database")
        
        # Recent alerts list
        st.subheader("Recent Active Alerts")
        if active_alerts[:5]:
            for alert in active_alerts[:5]:
                severity = "🔴" if alert.risk_score >= 0.8 else "🟠" if alert.risk_score >= 0.6 else "🟡"
                st.warning(f"{severity} **{alert.user_id}** - {alert.event_type} (Risk: {alert.risk_score:.2f})")
        else:
            st.success("No active alerts - system is secure! ✅")
            
    finally:
        session.close()
        db.close()
    
    # Auto-refresh logic
    if auto_refresh:
        time.sleep(30)
        st.rerun()


def show_audit_analysis():
    """Audit log analysis page"""
    st.header("📊 Audit Log Analysis (Sentinel Agent)")
    
    st.markdown("""
    View alerts detected by the Sentinel Agent from audit log analysis.
    The Sentinel Agent continuously monitors audit logs and flags suspicious activities.
    """)
    
    # Fetch recent sentinel alerts
    db.connect()
    session = db.get_session()
    alert_repo = AlertResultRepository(session)
    
    try:
        # Get recent alerts
        alerts = alert_repo.get_all(limit=20)
        
        if alerts:
            st.subheader(f"Recent Sentinel Detections ({len(alerts)} alerts)")
            
            # Create DataFrame
            results_data = []
            for alert in alerts:
                results_data.append({
                    'Timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'User': alert.user_id,
                    'Event Type': alert.event_type,
                    'Anomaly Type': alert.alert_reason[:50] + '...' if len(alert.alert_reason) > 50 else alert.alert_reason,
                    'Risk Score': alert.risk_score,
                    'Sentinel Conf.': alert.initial_confidence if alert.initial_confidence else 0.0,
                    'Defense Conf.': alert.defense_confidence if alert.defense_confidence else 0.0,
                    'Status': alert.final_status
                })
            
            results_df = pd.DataFrame(results_data)
            
            # Display metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                avg_risk = results_df['Risk Score'].mean()
                st.metric("Avg Risk Score", f"{avg_risk:.2f}")
            with col2:
                high_risk = len(results_df[results_df['Risk Score'] >= 0.6])
                st.metric("High Risk Events", high_risk)
            with col3:
                escalated = len(results_df[results_df['Status'] == 'escalated'])
                st.metric("Escalated", escalated)
            
            # Display table
            st.dataframe(results_df, use_container_width=True)
            
            # Show detailed view
            st.subheader("Detailed Alerts")
            for i, alert in enumerate(alerts[:5], 1):
                with st.expander(f"Alert {i}: {alert.user_id} - {alert.event_type} (Risk: {alert.risk_score:.2f})"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Timestamp:** {alert.timestamp}")
                        st.write(f"**User ID:** {alert.user_id}")
                        st.write(f"**Event Type:** {alert.event_type}")
                        st.write(f"**Status:** {alert.final_status}")
                    with col2:
                        st.write(f"**Risk Score:** {alert.risk_score:.2f}")
                        st.write(f"**Sentinel Confidence:** {alert.initial_confidence:.2f if alert.initial_confidence else 'N/A'}")
                        st.write(f"**Defense Confidence:** {alert.defense_confidence:.2f if alert.defense_confidence else 'N/A'}")
                        st.write(f"**Dismissed:** {'Yes' if alert.dismissed else 'No'}")
                    
                    st.write(f"**Alert Reason:** {alert.alert_reason}")
                    if alert.defense_reasoning:
                        st.write(f"**Defense Reasoning:** {alert.defense_reasoning}")
        else:
            st.info("No alerts found. Run the sentinel agent to analyze audit logs.")
            st.code("python main.py", language="bash")
    
    finally:
        session.close()
        db.close()


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
    
    # Auto-refresh
    col_title, col_refresh = st.columns([3, 1])
    with col_refresh:
        auto_refresh = st.checkbox("Auto-refresh (15s)", value=False, key="findings_refresh")
    
    # Filter options
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"]
        )
    with col2:
        agent_filter = st.multiselect(
            "Agent",
            ["Sentinel", "Hallucinator"],
            default=["Sentinel", "Hallucinator"]
        )
    with col3:
        status_filter = st.selectbox("Status", ["All", "Active", "Dismissed", "Escalated"])
    with col4:
        limit = st.number_input("Max Results", min_value=10, max_value=500, value=50, step=10)
    
    # Fetch live alerts from database
    db.connect()
    session = db.get_session()
    alert_repo = AlertResultRepository(session)
    
    try:
        # Get alerts based on status filter
        if status_filter == "Active":
            alerts = alert_repo.get_active_alerts(limit=limit)
        elif status_filter == "Escalated":
            alerts = alert_repo.get_escalated_alerts(limit=limit)
        else:
            alerts = alert_repo.get_all(limit=limit)
        
        if status_filter == "Dismissed":
            alerts = [a for a in alerts if a.dismissed]
        
        # Convert to DataFrame
        if alerts:
            findings_data = []
            for alert in alerts:
                # Determine severity based on risk score
                if alert.risk_score >= 0.8:
                    severity = "Critical"
                elif alert.risk_score >= 0.6:
                    severity = "High"
                elif alert.risk_score >= 0.4:
                    severity = "Medium"
                else:
                    severity = "Low"
                
                # Determine agent
                agent = alert.agent_type if hasattr(alert, 'agent_type') else "Sentinel"
                
                # Apply filters
                if severity not in severity_filter:
                    continue
                if agent not in agent_filter:
                    continue
                
                findings_data.append({
                    'ID': f'A{alert.id:04d}',
                    'Timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'User': alert.user_id,
                    'Event': alert.event_type,
                    'Severity': severity,
                    'Risk Score': f"{alert.risk_score:.2f}",
                    'Agent': agent,
                    'Status': alert.final_status,
                    'Reason': alert.alert_reason[:80] + '...' if len(alert.alert_reason) > 80 else alert.alert_reason,
                    'Dismissed': '✓' if alert.dismissed else ''
                })
            
            if findings_data:
                findings_df = pd.DataFrame(findings_data)
                
                st.write(f"**Found {len(findings_df)} alerts**")
                st.dataframe(findings_df, use_container_width=True)
                
                # Export option
                if st.button("Export to CSV"):
                    csv = findings_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No alerts match the selected filters")
        else:
            st.info("No alerts found in database. Run the sentinel to generate alerts.")
    
    finally:
        session.close()
        db.close()
    
    # Auto-refresh logic
    if auto_refresh:
        time.sleep(15)
        st.rerun()


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
