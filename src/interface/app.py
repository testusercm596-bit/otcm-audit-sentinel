"""
OTCM Audit Sentinel - Interactive Streamlit Dashboard
Real-time security monitoring and alert analysis
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.infrastructure.database import db
from src.infrastructure.repositories import AuditLogRepository
from src.infrastructure.alert_repository import AlertResultRepository
from config.settings import settings


# Page configuration
st.set_page_config(
    page_title="OTCM Audit Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .alert-box {
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
        cursor: pointer;
    }
    .alert-high {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
    }
    .alert-medium {
        background-color: #fff3e0;
        border-left: 5px solid #ff9800;
    }
    .alert-low {
        background-color: #e8f5e9;
        border-left: 5px solid #4caf50;
    }
    .log-normal {
        background-color: #f5f5f5;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .sentinel-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .hallucinator-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .metric-card {
        background-color: white;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


def init_database():
    """Initialize database connection"""
    if 'db_initialized' not in st.session_state:
        try:
            db.connect()
            st.session_state.db_initialized = True
            st.session_state.db_error = None
        except Exception as e:
            st.session_state.db_initialized = False
            st.session_state.db_error = str(e)


def get_recent_logs(limit=50):
    """Fetch recent audit logs"""
    session = db.get_session()
    try:
        audit_repo = AuditLogRepository(session)
        logs = audit_repo.get_all(limit=limit)
        return logs
    finally:
        session.close()


def get_recent_alerts(limit=30):
    """Fetch recent alert results"""
    session = db.get_session()
    try:
        alert_repo = AlertResultRepository(session)
        alerts = alert_repo.get_all(limit=limit)
        return alerts
    finally:
        session.close()


def get_alert_by_id(alert_id):
    """Fetch specific alert by ID"""
    session = db.get_session()
    try:
        alert_repo = AlertResultRepository(session)
        return alert_repo.get_by_id(alert_id)
    finally:
        session.close()


def update_alert_status(alert_id, status):
    """Update alert status"""
    session = db.get_session()
    try:
        alert_repo = AlertResultRepository(session)
        dismissed = (status == 'dismissed')
        alert_repo.update_status(alert_id, status, dismissed)
    finally:
        session.close()


def get_risk_color(risk_score):
    """Get color based on risk score"""
    if risk_score >= 0.7:
        return "alert-high"
    elif risk_score >= 0.4:
        return "alert-medium"
    else:
        return "alert-low"


def display_live_feed():
    """Display live feed of logs and alerts"""
    st.header("📡 Live Feed")
    
    # Refresh button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Refresh", key="refresh_feed"):
            st.revalidate_cache()
    
    # Get recent alerts
    alerts = get_recent_alerts(limit=30)
    
    if not alerts:
        st.info("No events recorded yet. Run main.py to start processing logs.")
        return
    
    # Display each alert/log
    for alert in alerts:
        with st.container():
            if alert.is_alert:
                # Display as alert
                risk_class = get_risk_color(alert.risk_score)
                
                st.markdown(f"""
                <div class="alert-box {risk_class}">
                    <strong>🚨 ALERT</strong> | {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>
                    <strong>User:</strong> {alert.user_id} | <strong>Action:</strong> {alert.event_type}<br>
                    <strong>Risk Score:</strong> {alert.risk_score:.2f} | <strong>Status:</strong> {alert.final_status.upper()}<br>
                    <small>{alert.alert_reason[:100]}...</small>
                </div>
                """, unsafe_allow_html=True)
                
                # Click to view details
                if st.button(f"View Details 🔍", key=f"view_{alert.id}"):
                    st.session_state.selected_alert_id = alert.id
                    st.rerun()
            else:
                # Display as normal log
                st.markdown(f"""
                <div class="log-normal">
                    <small>{alert.timestamp.strftime('%H:%M:%S')}</small> | 
                    <strong>{alert.user_id}</strong> | {alert.event_type}
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("---")


def display_security_debate(alert_id):
    """Display security debate for selected alert"""
    st.header("⚖️ Security Debate")
    
    # Get alert details
    alert = get_alert_by_id(alert_id)
    
    if not alert:
        st.error("Alert not found")
        return
    
    # Back button
    if st.button("⬅️ Back to Feed"):
        st.session_state.selected_alert_id = None
        st.rerun()
    
    # Alert summary
    st.subheader("📋 Event Summary")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Risk Score", f"{alert.risk_score:.2f}")
    with col2:
        st.metric("Defense Confidence", f"{alert.defense_confidence:.2f}" if alert.defense_confidence else "N/A")
    with col3:
        st.metric("Status", alert.final_status.upper())
    
    st.markdown(f"""
    **User:** {alert.user_id}  
    **Action:** {alert.event_type}  
    **Time:** {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
    """)
    
    st.markdown("---")
    
    # Two-column debate
    col_sentinel, col_hallucinator = st.columns(2)
    
    with col_sentinel:
        st.markdown("""
        <div class="sentinel-card">
            <h3>🔴 Sentinel Agent - Accusation</h3>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"**Risk Assessment:** {alert.risk_score:.2f} / 1.0")
        
        if alert.rule_triggered:
            st.markdown(f"**Rule Triggered:** {alert.rule_triggered}")
        
        if alert.distance_score:
            st.markdown(f"**Anomaly Distance:** {alert.distance_score:.2f}")
        
        st.markdown("**Reason:**")
        st.info(alert.alert_reason)
        
        st.markdown("**Sentinel Verdict:** ⚠️ SUSPICIOUS ACTIVITY DETECTED")
    
    with col_hallucinator:
        st.markdown("""
        <div class="hallucinator-card">
            <h3>🛡️ Hallucinator Agent - Defense</h3>
        </div>
        """, unsafe_allow_html=True)
        
        if alert.defense_generated:
            st.markdown(f"**Defense Confidence:** {alert.defense_confidence:.2f} / 1.0")
            
            st.markdown("**Justification:**")
            st.success(alert.defense_justification)
            
            if alert.supporting_evidence:
                st.markdown("**Supporting Evidence:**")
                for i, evidence in enumerate(alert.supporting_evidence, 1):
                    st.markdown(f"{i}. {evidence}")
            
            if alert.risk_mitigation:
                st.markdown("**Risk Mitigation:**")
                st.warning(alert.risk_mitigation)
            
            if alert.defense_confidence >= 0.7:
                st.markdown("**Defense Verdict:** ✅ LIKELY FALSE POSITIVE")
            else:
                st.markdown("**Defense Verdict:** ❌ INSUFFICIENT BENIGN EXPLANATION")
        else:
            st.error("No defense generated for this alert")
    
    st.markdown("---")
    
    # Decision buttons
    st.subheader("🎯 Your Decision")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("✅ Ignore (False Positive)", type="secondary", use_container_width=True):
            update_alert_status(alert_id, 'dismissed')
            st.success("Alert marked as dismissed")
            time.sleep(1)
            st.session_state.selected_alert_id = None
            st.rerun()
    
    with col2:
        if st.button("🚨 Investigate (Genuine Threat)", type="primary", use_container_width=True):
            update_alert_status(alert_id, 'escalated')
            st.error("Alert escalated for investigation")
            time.sleep(1)
            st.session_state.selected_alert_id = None
            st.rerun()
    
    with col3:
        st.caption(f"Current status: **{alert.final_status.upper()}**")


def display_dashboard_metrics():
    """Display dashboard metrics"""
    session = db.get_session()
    try:
        alert_repo = AlertResultRepository(session)
        
        # Get all alerts
        all_alerts = alert_repo.get_all(limit=1000)
        active_alerts = alert_repo.get_active_alerts()
        escalated_alerts = alert_repo.get_escalated_alerts()
        
        # Calculate metrics
        total_alerts = len([a for a in all_alerts if a.is_alert])
        dismissed_count = len([a for a in all_alerts if a.dismissed])
        escalated_count = len(escalated_alerts)
        active_count = len(active_alerts)
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Alerts", total_alerts)
        
        with col2:
            st.metric("Active Alerts", active_count, delta=None)
        
        with col3:
            st.metric("Dismissed", dismissed_count, delta=f"-{dismissed_count}")
        
        with col4:
            st.metric("Escalated", escalated_count, delta=f"+{escalated_count}")
        
    finally:
        session.close()


def main():
    """Main Streamlit app"""
    
    # Initialize database
    init_database()
    
    # Title
    st.title("🛡️ OTCM Audit Sentinel")
    st.caption("AI-Powered Security Analysis for OpenText Content Manager")
    
    # Check database connection
    if not st.session_state.get('db_initialized', False):
        st.error(f"❌ Database connection failed: {st.session_state.get('db_error', 'Unknown error')}")
        st.info("Make sure PostgreSQL is running and credentials are correct in .env file")
        return
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Controls")
        
        # Auto-refresh toggle
        auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)
        
        if auto_refresh:
            time.sleep(5)
            st.rerun()
        
        st.markdown("---")
        
        # System status
        st.subheader("📊 System Status")
        st.success("✅ Database Connected")
        st.info(f"🕐 {datetime.now().strftime('%H:%M:%S')}")
        
        st.markdown("---")
        
        # Quick stats
        st.subheader("📈 Quick Stats")
        display_dashboard_metrics()
        
        st.markdown("---")
        
        # Help
        with st.expander("❓ Help"):
            st.markdown("""
            **How to use:**
            1. View live feed in left column
            2. Click on alerts to see details
            3. Review Sentinel vs Hallucinator debate
            4. Make decision: Ignore or Investigate
            
            **Color codes:**
            - 🔴 Red: High risk (≥0.7)
            - 🟠 Orange: Medium risk (0.4-0.7)
            - 🟢 Green: Low risk (<0.4)
            """)
    
    # Main layout - Two columns
    col1, col2 = st.columns([1, 1])
    
    with col1:
        display_live_feed()
    
    with col2:
        if st.session_state.get('selected_alert_id'):
            display_security_debate(st.session_state.selected_alert_id)
        else:
            st.header("⚖️ Security Debate")
            st.info("👈 Click on an alert in the Live Feed to view the security debate")
            
            # Show example
            st.markdown("""
            ### How it works:
            
            When you click an alert, you'll see:
            
            **🔴 Sentinel Agent** (Left)
            - Risk assessment
            - Rules triggered
            - Anomaly detection results
            
            **🛡️ Hallucinator Agent** (Right)
            - Benign justification
            - Supporting evidence
            - Risk mitigation suggestions
            
            Make your decision based on both perspectives!
            """)


if __name__ == "__main__":
    main()
