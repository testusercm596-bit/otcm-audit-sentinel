"""
Example: Using Hallucinator with Training Data
Demonstrates how to leverage synthetic training data for better defense generation
"""
import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.application.hallucinator import HallucinatorAgent, DefenseContext


def load_training_data():
    """Load the generated training examples"""
    training_file = Path(__file__).parent.parent / "scripts" / "hallucinator_training_examples.json"
    
    if not training_file.exists():
        print(f"⚠️  Training file not found: {training_file}")
        print("   Run 'python scripts/train_hallucinator_with_data.py' first")
        return []
    
    with open(training_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def format_training_context(training_examples, pattern_type='normal_pattern'):
    """Format training examples for use in prompts"""
    relevant_examples = [ex for ex in training_examples if ex['type'] == pattern_type]
    
    context = []
    for example in relevant_examples[:3]:  # Use top 3 examples
        user = example['user']
        event_count = len(example['events'])
        justification = example['justification']
        context.append(f"- User '{user}': {event_count} events - {justification}")
    
    return "\n".join(context)


def example_defense_with_training_context():
    """Generate defense using training data context"""
    print("=" * 70)
    print("Example: Hallucinator Defense with Training Data Context")
    print("=" * 70)
    
    # Load training data
    print("\n📚 Loading training data...")
    training_examples = load_training_data()
    if not training_examples:
        return
    
    print(f"✓ Loaded {len(training_examples)} training examples")
    
    # Count examples by type
    types = {}
    for ex in training_examples:
        types[ex['type']] = types.get(ex['type'], 0) + 1
    print(f"  Training patterns: {types}")
    
    # Create hallucinator agent (using mock mode without API credentials)
    agent = HallucinatorAgent(model="gpt-4", temperature=0.7)
    
    # Scenario: User performing delete operations after hours
    alert = {
        'is_alert': True,
        'risk_score': 0.72,
        'reason': 'Multiple delete operations performed outside business hours',
        'event': {
            'user_id': 'pnayak2',
            'event_type': 'DELETE',
            'timestamp': '2026-02-05T22:30:00',
            'record_type': 'Document',
            'record_title': 'Old_Project_Files',
            'count': 5,
            'time_of_day': 'Late Night (10:30 PM)'
        }
    }
    
    # User history (simulated)
    user_history = [
        {'event_type': 'READ', 'timestamp': '2026-02-05T09:15:00', 'record_type': 'Document'},
        {'event_type': 'READ', 'timestamp': '2026-02-05T14:30:00', 'record_type': 'Document'},
        {'event_type': 'WRITE', 'timestamp': '2026-02-05T16:45:00', 'record_type': 'Document'},
        {'event_type': 'DELETE', 'timestamp': '2026-02-05T22:30:00', 'record_type': 'Document'},
        {'event_type': 'DELETE', 'timestamp': '2026-02-05T22:35:00', 'record_type': 'Document'},
    ]
    
    print("\n🚨 Alert Details:")
    print(f"  Risk Score: {alert['risk_score']}")
    print(f"  Reason: {alert['reason']}")
    print(f"  User: {alert['event']['user_id']}")
    print(f"  Time: {alert['event']['time_of_day']}")
    print(f"  Event: {alert['event']['event_type']} - {alert['event']['record_type']}")
    
    # Find similar training patterns
    off_hours_examples = [ex for ex in training_examples if ex['type'] == 'off_hours']
    normal_examples = [ex for ex in training_examples if ex['type'] == 'normal_pattern']
    
    print(f"\n🔍 Found {len(off_hours_examples)} off-hours training examples")
    print(f"🔍 Found {len(normal_examples)} normal pattern examples")
    
    # Generate defense
    print("\n⚖️  Generating defense with training context...")
    defense = agent.generate_defense(alert, user_history)
    
    print("\n" + "=" * 70)
    print("Defense Context Generated:")
    print("=" * 70)
    print(f"\nJustification:")
    print(f"  {defense.justification}")
    print(f"\nConfidence: {defense.confidence:.2%}")
    
    if defense.supporting_evidence:
        print(f"\nSupporting Evidence:")
        for i, evidence in enumerate(defense.supporting_evidence, 1):
            print(f"  {i}. {evidence}")
    
    if defense.risk_mitigation:
        print(f"\nRisk Mitigation:")
        print(f"  {defense.risk_mitigation}")
    
    # Show how training data influenced the decision
    print("\n" + "=" * 70)
    print("Training Data Insights:")
    print("=" * 70)
    
    if off_hours_examples:
        print("\n📖 Off-Hours Patterns Learned:")
        for ex in off_hours_examples[:2]:
            print(f"  • {ex['user']}: {ex['justification']}")
    
    print("\n💡 Recommendation:")
    if defense.confidence > 0.6:
        print("  This alert likely represents LEGITIMATE activity based on:")
        print("  1. Historical off-hours work patterns")
        print("  2. User's normal behavior during daytime")
        print("  3. Contextual factors (cleanup, deadlines, etc.)")
    else:
        print("  This alert requires FURTHER INVESTIGATION:")
        print("  1. Verify with user if this was authorized")
        print("  2. Check deletion targets for sensitivity")
        print("  3. Review recent access logs")


def example_pattern_matching():
    """Example: Match current alert against training patterns"""
    print("\n\n" + "=" * 70)
    print("Example: Pattern Matching with Training Data")
    print("=" * 70)
    
    training_examples = load_training_data()
    if not training_examples:
        return
    
    # Current event to analyze
    current_event = {
        'user': 'opentext\\jsmith',
        'event_type': 'Added',
        'object_type': 'Record',
        'timestamp': '2026-02-06T14:30:00',
        'is_violation': False
    }
    
    print(f"\n🔍 Analyzing Event:")
    print(f"  User: {current_event['user']}")
    print(f"  Type: {current_event['event_type']} - {current_event['object_type']}")
    print(f"  Time: Feb 6, 2026 at 2:30 PM")
    
    # Find matching patterns
    matches = []
    for example in training_examples:
        if example['user'] == current_event['user']:
            if example['type'] == 'normal_pattern':
                matches.append({
                    'type': 'exact_user_match',
                    'pattern': example,
                    'score': 1.0
                })
    
    print(f"\n✓ Found {len(matches)} matching patterns")
    
    if matches:
        print("\n📊 Pattern Analysis:")
        for match in matches[:2]:
            pattern = match['pattern']
            print(f"\n  Pattern Type: {pattern['type']}")
            print(f"  User: {pattern['user']}")
            print(f"  Events: {len(pattern['events'])}")
            print(f"  Label: {pattern['label']}")
            print(f"  Assessment: {pattern['justification']}")
    
    # Decision
    print("\n🎯 Decision:")
    if matches and all(m['pattern']['label'] == 'benign' for m in matches):
        print("  ✅ Event matches NORMAL BEHAVIOR patterns")
        print("  → No alert needed")
    else:
        print("  ⚠️  Event requires further analysis")
        print("  → Generate defense or escalate")


def show_training_statistics():
    """Display statistics about training data"""
    print("\n\n" + "=" * 70)
    print("Training Data Statistics")
    print("=" * 70)
    
    training_examples = load_training_data()
    if not training_examples:
        return
    
    users = set()
    types = {}
    labels = {}
    total_events = 0
    
    for example in training_examples:
        users.add(example['user'])
        types[example['type']] = types.get(example['type'], 0) + 1
        labels[example['label']] = labels.get(example['label'], 0) + 1
        total_events += len(example['events'])
    
    print(f"\n📊 Overview:")
    print(f"  Total Training Examples: {len(training_examples)}")
    print(f"  Unique Users: {len(users)}")
    print(f"  Total Events Covered: {total_events}")
    print(f"  Avg Events per Example: {total_events/len(training_examples):.1f}")
    
    print(f"\n📈 Pattern Types:")
    for ptype, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(training_examples) * 100
        print(f"  {ptype:20s}: {count:2d} ({pct:5.1f}%)")
    
    print(f"\n🏷️  Labels:")
    for label, count in sorted(labels.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(training_examples) * 100
        print(f"  {label:30s}: {count:2d} ({pct:5.1f}%)")
    
    print(f"\n👥 Users Covered:")
    for user in sorted(users):
        user_examples = [ex for ex in training_examples if ex['user'] == user]
        print(f"  {user:30s}: {len(user_examples)} examples")


def main():
    """Run all examples"""
    print("\n🎯 Hallucinator Training Data Examples\n")
    
    # Example 1: Defense with training context
    example_defense_with_training_context()
    
    # Example 2: Pattern matching
    example_pattern_matching()
    
    # Example 3: Statistics
    show_training_statistics()
    
    print("\n\n" + "=" * 70)
    print("✅ Examples completed!")
    print("=" * 70)
    print("\n📖 Next Steps:")
    print("  1. Review hallucinator_training_examples.json")
    print("  2. Generate more synthetic data for edge cases")
    print("  3. Integrate with vector database for similarity search")
    print("  4. Fine-tune hallucinator prompts with examples")
    print("\n")


if __name__ == "__main__":
    main()
