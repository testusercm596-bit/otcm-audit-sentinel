"""
Example usage of Sentinel Agent for security event evaluation
"""
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.application.sentinel import SentinelAgent, SecurityAlert, UserProfile


def example_basic_usage():
    """Example: Basic Sentinel Agent usage with rules"""
    print("=" * 60)
    print("Example 1: Basic Rule-Based Detection")
    print("=" * 60)
    
    # Define security rules
    rules = [
        {
            'name': 'Excessive Deletes',
            'condition': 'event_type',
            'operator': '==',
            'value': 'DELETE',
            'threshold': 3,
            'risk_score': 0.8,
            'description': 'User performed more than 3 delete operations'
        },
        {
            'name': 'Sensitive Document Access',
            'condition': 'event_type',
            'operator': '==',
            'value': 'ACCESS_SENSITIVE',
            'threshold': None,
            'risk_score': 0.9,
            'description': 'Attempt to access sensitive document'
        }
    ]
    
    # Create user profiles
    user_profiles = {
        "john.doe": UserProfile(
            user_id="john.doe",
            baseline_embedding=[0.5] * 10  # 10D baseline vector
        )
    }
    
    # Initialize agent
    agent = SentinelAgent(rules=rules, user_profiles=user_profiles)
    
    # Test normal event
    print("\n📝 Testing normal READ event:")
    event1 = {
        'user_id': 'john.doe',
        'event_type': 'READ',
        'timestamp': '2026-02-05T10:00:00'
    }
    alert1 = agent.evaluate_event(event1)
    print(f"  Alert: {alert1.is_alert}")
    print(f"  Risk Score: {alert1.risk_score}")
    print(f"  Reason: {alert1.reason}")
    
    # Test sensitive access
    print("\n🚨 Testing sensitive document access:")
    event2 = {
        'user_id': 'john.doe',
        'event_type': 'ACCESS_SENSITIVE',
        'timestamp': '2026-02-05T10:05:00'
    }
    alert2 = agent.evaluate_event(event2)
    print(f"  Alert: {alert2.is_alert}")
    print(f"  Risk Score: {alert2.risk_score}")
    print(f"  Reason: {alert2.reason}")
    print(f"  Rule Triggered: {alert2.rule_triggered}")


def example_threshold_detection():
    """Example: Threshold-based detection (excessive deletes)"""
    print("\n" + "=" * 60)
    print("Example 2: Threshold-Based Detection")
    print("=" * 60)
    
    rules = [
        {
            'name': 'Excessive Deletes',
            'condition': 'event_type',
            'operator': '==',
            'value': 'DELETE',
            'threshold': 3,
            'risk_score': 0.8,
            'description': 'Too many delete operations detected'
        }
    ]
    
    agent = SentinelAgent(rules=rules, user_profiles={})
    
    print("\n📊 Simulating multiple DELETE events:")
    
    # Simulate 5 delete events
    for i in range(5):
        event = {
            'user_id': 'jane.smith',
            'event_type': 'DELETE',
            'timestamp': f'2026-02-05T10:{i:02d}:00'
        }
        alert = agent.evaluate_event(event)
        
        print(f"\n  Delete #{i+1}:")
        print(f"    Alert: {alert.is_alert}")
        print(f"    Risk Score: {alert.risk_score}")
        if alert.is_alert:
            print(f"    ⚠️  THRESHOLD EXCEEDED!")
            print(f"    Reason: {alert.reason}")


def example_anomaly_detection():
    """Example: Anomaly detection using embedding distance"""
    print("\n" + "=" * 60)
    print("Example 3: Anomaly Detection with Embeddings")
    print("=" * 60)
    
    # Create user profile with baseline behavior
    baseline_embedding = [0.5, 0.5, 0.5, 0.5, 0.5]  # 5D vector
    user_profile = UserProfile(
        user_id="bob.johnson",
        baseline_embedding=baseline_embedding
    )
    
    agent = SentinelAgent(rules=[], user_profiles={"bob.johnson": user_profile})
    
    # Test normal event (close to baseline)
    print("\n✅ Testing normal event (close to baseline):")
    normal_event = {
        'user_id': 'bob.johnson',
        'event_type': 'READ',
        'timestamp': '2026-02-05T10:00:00',
        'embedding': [0.5, 0.5, 0.5, 0.5, 0.5]  # Same as baseline
    }
    alert1 = agent.evaluate_event(normal_event)
    print(f"  Alert: {alert1.is_alert}")
    print(f"  Risk Score: {alert1.risk_score}")
    print(f"  Distance: {alert1.distance_score if alert1.distance_score else 'N/A'}")
    
    # Test moderately anomalous event
    print("\n⚠️  Testing moderately anomalous event:")
    moderate_event = {
        'user_id': 'bob.johnson',
        'event_type': 'WRITE',
        'timestamp': '2026-02-05T11:00:00',
        'embedding': [1.5, 1.5, 1.5, 1.5, 1.5]  # Moderate deviation
    }
    alert2 = agent.evaluate_event(moderate_event)
    print(f"  Alert: {alert2.is_alert}")
    print(f"  Risk Score: {alert2.risk_score}")
    print(f"  Distance: {alert2.distance_score:.2f}")
    print(f"  Reason: {alert2.reason}")
    
    # Test highly anomalous event
    print("\n🚨 Testing highly anomalous event:")
    anomalous_event = {
        'user_id': 'bob.johnson',
        'event_type': 'DELETE',
        'timestamp': '2026-02-05T12:00:00',
        'embedding': [5.0, 5.0, 5.0, 5.0, 5.0]  # Large deviation
    }
    alert3 = agent.evaluate_event(anomalous_event)
    print(f"  Alert: {alert3.is_alert}")
    print(f"  Risk Score: {alert3.risk_score}")
    print(f"  Distance: {alert3.distance_score:.2f}")
    print(f"  Reason: {alert3.reason}")


def example_combined_detection():
    """Example: Combined rule-based and anomaly detection"""
    print("\n" + "=" * 60)
    print("Example 4: Combined Rule-Based + Anomaly Detection")
    print("=" * 60)
    
    # Rules
    rules = [
        {
            'name': 'Admin Operations',
            'condition': 'event_type',
            'operator': '==',
            'value': 'ADMIN_CHANGE',
            'threshold': None,
            'risk_score': 0.95,
            'description': 'Administrative change detected'
        }
    ]
    
    # User profiles with baselines
    user_profiles = {
        "alice.williams": UserProfile(
            user_id="alice.williams",
            baseline_embedding=[0.3, 0.3, 0.3]
        )
    }
    
    agent = SentinelAgent(rules=rules, user_profiles=user_profiles)
    
    print("\n🔍 Testing various events:")
    
    test_events = [
        {
            'name': 'Normal READ',
            'event': {
                'user_id': 'alice.williams',
                'event_type': 'READ',
                'timestamp': '2026-02-05T09:00:00',
                'embedding': [0.3, 0.3, 0.3]
            }
        },
        {
            'name': 'Anomalous WRITE',
            'event': {
                'user_id': 'alice.williams',
                'event_type': 'WRITE',
                'timestamp': '2026-02-05T09:30:00',
                'embedding': [2.0, 2.0, 2.0]
            }
        },
        {
            'name': 'Rule Trigger: ADMIN_CHANGE',
            'event': {
                'user_id': 'alice.williams',
                'event_type': 'ADMIN_CHANGE',
                'timestamp': '2026-02-05T10:00:00'
            }
        }
    ]
    
    for test in test_events:
        print(f"\n  📋 {test['name']}:")
        alert = agent.evaluate_event(test['event'])
        print(f"    Alert: {alert.is_alert}")
        print(f"    Risk Score: {alert.risk_score}")
        if alert.rule_triggered:
            print(f"    Rule: {alert.rule_triggered}")
        if alert.distance_score:
            print(f"    Distance: {alert.distance_score:.2f}")
        print(f"    Reason: {alert.reason}")


def main():
    """Run all examples"""
    print("\n🛡️  Sentinel Agent Examples\n")
    
    try:
        example_basic_usage()
        example_threshold_detection()
        example_anomaly_detection()
        example_combined_detection()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
