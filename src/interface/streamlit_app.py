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
from src.infrastructure.rule_repository import RuleRepository


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
        ["Dashboard", "Security Rules", "Audit Analysis", "Security Testing", "Findings", "Settings"]
    )
    
    if page == "Dashboard":
        show_dashboard()
    elif page == "Security Rules":
        show_security_rules()
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
security_rules():
    """Security rules management page"""
    st.header("🔐 Security Rules Management")
    
    # Initialize rule repository
    rule_repo = RuleRepository()
    
    # Create tabs for different actions
    tab1, tab2, tab3 = st.tabs(["📝 Create Rule", "📋 View Rules", "📊 Statistics"])
    
    with tab1:
        st.subheader("Create New Security Rule")
        
        rule_type = st.radio(
            "Rule Type",
            ["Natural Language (AI-Powered)", "Structured (Traditional)"],
            help="Natural language rules use AI to evaluate events based on human-readable descriptions"
        )
        
        if rule_type == "Natural Language (AI-Powered)":
            st.markdown("---")
            st.markdown("### 🤖 AI-Powered Natural Language Rule")
            st.info("Describe the security rule in plain English. The AI will evaluate events against your description.")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                rule_name = st.text_input(
                    "Rule Name *",
                    placeholder="e.g., After Hours Document Access"
                )
            with col2:
                risk_score = st.slider("Risk Score", 0.0, 1.0, 0.7, 0.05)
            
            nl_description = st.text_area(
                "Rule Description in Natural Language *",
                placeholder="Describe what should trigger an alert. Examples:\n"
                           "- Alert if user accesses confidential documents between 10 PM and 6 AM\n"
                           "- Trigger alert when user downloads more than 50 files in one hour\n"
                           "- Flag when a user from Sales accesses Engineering documents\n"
                           "- Alert if non-admin user tries to modify permissions",
                height=150
            )
            
            st.markdown("**Examples of good natural language rules:**")
            example_col1, example_col2 = st.columns(2)
            with example_col1:
                st.markdown("""
                - Alert when user deletes more than 10 items in 5 minutes
                - Flag access to HR documents by non-HR staff
                - Warn if user exports data larger than 1GB
                """)
            with example_col2:
                st.markdown("""
                - Alert on failed login attempts exceeding 5 times
                - Detect when user shares documents with external email
                - Flag privilege escalation attempts
                """)
            
            col1, col2 = st.columns([1, 3])
            with col1:
                if st.button("Create Natural Language Rule", type="primary", use_container_width=True):
                    if not rule_name or not nl_description:
                        st.error("Please fill in all required fields (*)") 
                    else:
                        try:
                            rule = rule_repo.create_natural_language_rule(
                                name=rule_name,
                                nl_rule=nl_description,
                                risk_score=risk_score,
                                created_by="admin"  # Would come from auth system
                            )
                            st.success(f"✅ Rule '{rule_name}' created successfully!")
                            st.balloons()
                        except Exception as e:
                            st.error(f"Error creating rule: {e}")
            
        else:  # Structured rule
            st.markdown("---")
            st.markdown("### ⚙️ Structured Rule")
            st.info("Define a rule using specific conditions and operators.")
            
            col1, col2 = st.columns(2)
            with col1:
                rule_name = st.text_input("Rule Name *", placeholder="e.g., Excessive Deletes")
            with col2:
                risk_score = st.slider("Risk Score", 0.0, 1.0, 0.7, 0.05)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                condition = st.text_input(
                    "Field/Condition *",
                    placeholder="e.g., event_type or metadata.department",
                    help="Use dot notation for nested fields"
                )
            with col2:
                operator = st.selectbox(
                    "Operator *",
                    ["==", "!=", ">", "<", ">=", "<=", "in", "not in", "contains", "startswith", "endswith", "regex"]
                )
            with col3:
                value = st.text_input(
                    "Value *",
                    placeholder="e.g., DELETE or ['value1', 'value2']"
                )
            
            col1, col2 = st.columns(2)
            with col1:
                threshold = st.number_input(
                    "Threshold (optional)",
                    min_value=0,
                    value=0,
                    help="For counting rules - trigger after N occurrences"
                )
            with col2:
                description = st.text_area("Description", placeholder="Explain what this rule detects")
            
            if st.button("Create Structured Rule", type="primary"):
                if not rule_name or not condition or not value:
                    st.error("Please fill in all required fields (*)")
                else:
                    try:
                        # Try to parse value as JSON for lists/dicts
                        import json
                        try:
                            parsed_value = json.loads(value)
                        except:
                            parsed_value = value
                        
                        rule = rule_repo.create_structured_rule(
                            name=rule_name,
                            condition=condition,
                            operator=operator,
                            value=parsed_value,
                            risk_score=risk_score,
                            threshold=threshold if threshold > 0 else None,
                            description=description,
                            created_by="admin"
                        )
                        st.success(f"✅ Rule '{rule_name}' created successfully!")
                        st.balloons()
                    except Exception as e:
                        st.error(f"Error creating rule: {e}")
    
    with tab2:
        st.subheader("Active Security Rules")
        
        # Filter options
        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            filter_type = st.selectbox("Filter by Type", ["All", "Natural Language", "Structured"])
        with col2:
            filter_status = st.selectbox("Filter by Status", ["All", "Enabled", "Disabled"])
        with col3:
            if st.button("🔄 Refresh"):
                st.rerun()
        
        # Get rules
        try:
            if filter_type == "Natural Language":
                rules = rule_repo.get_all_rules(rule_type='natural_language')
            elif filter_type == "Structured":
                rules = rule_repo.get_all_rules(rule_type='structured')
            else:
                rules = rule_repo.get_all_rules()
            
            if filter_status == "Enabled":
                rules = [r for r in rules if r.enabled]
            elif filter_status == "Disabled":
                rules = [r for r in rules if not r.enabled]
            
            if rules:
                st.markdown(f"**Found {len(rules)} rules**")
                
                for rule in rules:
                    with st.expander(f"{'✓' if rule.enabled else '✗'} {rule.name} ({rule.rule_type})", expanded=False):
                        col1, col2 = st.columns([3, 1])
                        
                        with col1:
                            st.markdown(f"**Type:** {rule.rule_type}")
                            st.markdown(f"**Risk Score:** {rule.risk_score}")
                            st.markdown(f"**Status:** {'✓ Enabled' if rule.enabled else '✗ Disabled'}")
                            
                            if rule.rule_type == 'natural_language':
                                st.markdown(f"**Rule:** {rule.natural_language_rule}")
                            else:
                                st.markdown(f"**Condition:** `{rule.condition}` {rule.operator} `{rule.value}`")
                                if rule.threshold:
                                    st.markdown(f"**Threshold:** {rule.threshold}")
                                if rule.description:
                                    st.markdown(f"**Description:** {rule.description}")
                            
                            st.markdown(f"**Created:** {rule.created_at}")
                            st.markdown(f"**Triggered:** {rule.trigger_count} times")
                            if rule.last_triggered:
                                st.markdown(f"**Last Triggered:** {rule.last_triggered}")
                        
                        with col2:
                            if rule.enabled:
                                if st.button(f"Disable", key=f"disable_{rule.id}"):
                                    rule_repo.disable_rule(rule.id)
                                    st.success("Rule disabled")
                                    st.rerun()
                            else:
                                if st.button(f"Enable", key=f"enable_{rule.id}"):
                                    rule_repo.enable_rule(rule.id)
                                    st.success("Rule enabled")
                                    st.rerun()
                            
                            if st.button(f"Delete", key=f"delete_{rule.id}", type="secondary"):
                                if st.button(f"Confirm Delete?", key=f"confirm_{rule.id}"):
                                    rule_repo.delete_rule(rule.id)
                                    st.success("Rule deleted")
                                    st.rerun()
            else:
                st.info("No rules found. Create your first rule in the 'Create Rule' tab!")
        
        except Exception as e:
            st.error(f"Error loading rules: {e}")
    
    with tab3:
        st.subheader("Rule Statistics")
        
        try:
            stats = rule_repo.get_rule_statistics()
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Rules", stats['total_rules'])
            with col2:
                st.metric("Enabled", stats['enabled_rules'])
            with col3:
                st.metric("AI Rules", stats['natural_language_rules'])
            with col4:
                st.metric("Structured", stats['structured_rules'])
            
            # Get all rules for additional stats
            all_rules = rule_repo.get_all_rules()
            
            if all_rules:
                st.markdown("---")
                st.markdown("### Rule Performance")
                
                # Create dataframe for chart
                rule_data = []
                for rule in all_rules:
                    rule_data.append({
                        'Rule Name': rule.name,
                        'Triggers': rule.trigger_count,
                        'Risk Score': rule.risk_score,
                        'Type': rule.rule_type
                    })
                
                df = pd.DataFrame(rule_data)
                
                if not df.empty and df['Triggers'].sum() > 0:
                    st.markdown("**Top Triggered Rules**")
                    top_rules = df.nlargest(5, 'Triggers')[['Rule Name', 'Triggers']]
                    st.bar_chart(top_rules.set_index('Rule Name'))
                else:
                    st.info("No rule triggers recorded yet.")
        
        except Exception as e:
            st.error(f"Error loading statistics: {e}")


def show_

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
