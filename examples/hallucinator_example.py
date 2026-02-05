"""
Example usage of Hallucinator Agent for generating defenses for security alerts
"""
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.application.hallucinator import HallucinatorAgent, DefenseContext
from src.application.sentinel import SentinelAgent, UserProfile


def example_basic_defense():
    """Example: Generate defense for a basic alert"""
    print("=" * 60)
    print("Example 1: Basic Defense Generation")
    print("=" * 60)
    
    # Create Hallucinator Agent with Aviator Model
    agent = HallucinatorAgent(
        model="openai/meta-llama/Llama-3.3-70B-Instruct",
        temperature=0.7,
        api_key="your_api_key_here",
        api_base="https://sandbox.aviator-model.bp.anthos.otxlab.net/v1"
    )
    # Or use without API credentials for mock mode:
    # agent = HallucinatorAgent(model="gpt-4", temperature=0.7)
    
    # Sample alert
    alert = {
        'is_alert': True,
        'risk_score': 0.8,
        'reason': 'User performed more than 5 delete operations',
        'event': {
            'user_id': 'john.doe',
            'event_type': 'DELETE',
            'timestamp': '2026-02-05T16:30:00',
            'record_type': 'Document',
            'record_title': 'Archive_Q4_2025.pdf'
        }
    }
    
    # User history
    user_history = [
        {'event_type': 'READ', 'timestamp': '2026-02-05T09:00:00', 'record_type': 'Document'},
        {'event_type': 'WRITE', 'timestamp': '2026-02-05T10:30:00', 'record_type': 'Document'},
        {'event_type': 'DELETE', 'timestamp': '2026-02-05T16:00:00', 'record_type': 'Document'},
    ]
    
    # Generate defense
    defense = agent.generate_defense(alert, user_history)
    
    print(f"\n🔍 Alert Details:")
    print(f"  Risk Score: {alert['risk_score']}")
    print(f"  Reason: {alert['reason']}")
    
    print(f"\n🛡️  Defense Generated:")
    print(f"  Confidence: {defense.confidence:.2f}")
    print(f"  Justification: {defense.justification}")
    
    if defense.supporting_evidence:
        print(f"\n  📋 Supporting Evidence:")
        for i, evidence in enumerate(defense.supporting_evidence, 1):
            print(f"    {i}. {evidence}")
    
    if defense.risk_mitigation:
        print(f"\n  ⚠️  Risk Mitigation:")
        print(f"    {defense.risk_mitigation}")


def example_after_hours_access():
    """Example: Defend after-hours access alert"""
    print("\n" + "=" * 60)
    print("Example 2: After-Hours Access Defense")
    print("=" * 60)
    
    # Using mock mode (no API credentials)
    agent = HallucinatorAgent()
    
    alert = {
        'is_alert': True,
        'risk_score': 0.6,
        'reason': 'Access during unusual hours (2:00 AM)',
        'event': {
            'user_id': 'jane.smith',
            'event_type': 'READ',
            'timestamp': '2026-02-05T02:15:00',
            'record_type': 'Contract',
            'record_title': 'Client_Agreement_APAC.pdf'
        }
    }
    
    user_history = [
        {'event_type': 'READ', 'timestamp': '2026-02-04T09:00:00', 'record_type': 'Email'},
        {'event_type': 'READ', 'timestamp': '2026-02-04T14:30:00', 'record_type': 'Contract'},
    ]
    
    defense = agent.generate_defense(alert, user_history)
    
    print(f"\n🔍 Alert: {alert['reason']}")
    print(f"\n🛡️  Defense (Confidence: {defense.confidence:.2f}):")
    print(f"  {defense.justification}")
    
    print(f"\n  Decision: {'✅ DISMISS ALERT' if agent.should_dismiss_alert(defense) else '⚠️  KEEP ALERT'}")


def example_anomaly_defense():
    """Example: Defend behavioral anomaly"""
    print("\n" + "=" * 60)
    print("Example 3: Behavioral Anomaly Defense")
    print("=" * 60)
    
    agent = HallucinatorAgent()
    
    alert = {
        'is_alert': True,
        'risk_score': 0.7,
        'reason': 'Moderate anomaly detected: Event deviates from user baseline',
        'event': {
            'user_id': 'bob.johnson',
            'event_type': 'WRITE',
            'timestamp': '2026-02-05T11:00:00',
            'record_type': 'Financial_Report',
            'record_title': 'Revenue_Analysis_2026.xlsx'
        }
    }
    
    # Rich user history showing normal pattern
    user_history = [
        {'event_type': 'READ', 'timestamp': '2026-01-15T10:00:00', 'record_type': 'Email'},
        {'event_type': 'READ', 'timestamp': '2026-01-16T11:00:00', 'record_type': 'Document'},
        {'event_type': 'READ', 'timestamp': '2026-01-17T09:30:00', 'record_type': 'Email'},
        {'event_type': 'WRITE', 'timestamp': '2026-01-18T14:00:00', 'record_type': 'Document'},
        {'event_type': 'READ', 'timestamp': '2026-01-19T10:00:00', 'record_type': 'Document'},
    ]
    
    defense = agent.generate_defense(alert, user_history)
    
    print(f"\n🔍 Alert: {alert['reason']}")
    print(f"  User typically accesses: Email, Documents")
    print(f"  Now accessing: Financial_Report (unusual)")
    
    print(f"\n🛡️  Defense (Confidence: {defense.confidence:.2f}):")
    print(f"  {defense.justification}")
    
    if defense.supporting_evidence:
        print(f"\n  📋 Evidence:")
        for evidence in defense.supporting_evidence[:3]:
            print(f"    • {evidence}")


def example_high_risk_alert():
    """Example: Try to defend high-risk admin alert (should fail)"""
    print("\n" + "=" * 60)
    print("Example 4: High-Risk Admin Alert (Low Defense Confidence)")
    print("=" * 60)
    
    agent = HallucinatorAgent()
    
    alert = {
        'is_alert': True,
        'risk_score': 0.95,
        'reason': 'Unauthorized admin access attempt',
        'event': {
            'user_id': 'regular.user',
            'event_type': 'ADMIN_ACCESS',
            'timestamp': '2026-02-05T22:30:00',
            'record_type': 'System',
            'record_title': 'Admin_Console'
        }
    }
    
    user_history = [
        {'event_type': 'READ', 'timestamp': '2026-02-05T09:00:00', 'record_type': 'Document'},
        {'event_type': 'WRITE', 'timestamp': '2026-02-05T10:00:00', 'record_type': 'Document'},
    ]
    
    defense = agent.generate_defense(alert, user_history)
    
    print(f"\n🚨 Critical Alert: {alert['reason']}")
    print(f"  Risk Score: {alert['risk_score']}")
    
    print(f"\n🛡️  Defense Attempt (Confidence: {defense.confidence:.2f}):")
    print(f"  {defense.justification}")
    
    print(f"\n  Decision: {'✅ DISMISS' if agent.should_dismiss_alert(defense) else '❌ CANNOT DISMISS - INVESTIGATE'}")
    
    if defense.risk_mitigation:
        print(f"\n  🚨 Recommended Action:")
        print(f"    {defense.risk_mitigation}")


def example_combined_sentinel_hallucinator():
    """Example: Combine Sentinel detection with Hallucinator defense"""
    print("\n" + "=" * 60)
    print("Example 5: Combined Sentinel Detection + Hallucinator Defense")
    print("=" * 60)
    
    # Setup Sentinel
    rules = [
        {
            'name': 'Excessive Deletes',
            'condition': 'event_type',
            'operator': '==',
            'value': 'DELETE',
            'threshold': 3,
            'risk_score': 0.8,
            'description': 'Too many delete operations'
        }
    ]
    
    user_profile = UserProfile(user_id="alice.williams", baseline_embedding=[0.5] * 5)
    sentinel = SentinelAgent(rules=rules, user_profiles={"alice.williams": user_profile})
    
    # Setup Hallucinator
    hallucinator = HallucinatorAgent()
    
    print("\n🔍 Step 1: Sentinel Detection")
    
    # Simulate 4 DELETE events
    for i in range(4):
        event = {
            'user_id': 'alice.williams',
            'event_type': 'DELETE',
            'timestamp': f'2026-02-05T14:{i:02d}:00',
            'record_type': 'Document'
        }
        alert = sentinel.evaluate_event(event)
        
        if alert.is_alert:
            print(f"  ⚠️  Alert triggered on delete #{i+1}")
            print(f"      Risk Score: {alert.risk_score}")
            
            # Get user history for defense
            user_history = [
                {'event_type': 'READ', 'timestamp': '2026-02-05T09:00:00', 'record_type': 'Document'},
                {'event_type': 'DELETE', 'timestamp': '2026-02-05T14:00:00', 'record_type': 'Document'},
            ]
            
            print(f"\n🛡️  Step 2: Hallucinator Defense")
            defense = hallucinator.generate_defense(
                {
                    'is_alert': True,
                    'risk_score': alert.risk_score,
                    'reason': alert.reason,
                    'event': event
                },
                user_history
            )
            
            print(f"  Defense Confidence: {defense.confidence:.2f}")
            print(f"  Justification: {defense.justification[:100]}...")
            
            print(f"\n📊 Final Decision:")
            if hallucinator.should_dismiss_alert(defense, confidence_threshold=0.7):
                print(f"  ✅ Alert DISMISSED (False Positive)")
                print(f"     Reason: High confidence benign explanation")
            else:
                print(f"  🚨 Alert ESCALATED for Investigation")
                print(f"     Reason: Cannot find sufficient benign justification")
            
            break


def main():
    """Run all examples"""
    print("\n🛡️  Hallucinator Agent Examples - AI Defense Attorney\n")
    
    try:
        example_basic_defense()
        example_after_hours_access()
        example_anomaly_defense()
        example_high_risk_alert()
        example_combined_sentinel_hallucinator()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
