"""
Train Hallucinator with generated audit log data

This script:
1. Loads generated audit logs
2. Converts them to embeddings
3. Stores them in the vector database (pgvector)
4. Creates training examples for the hallucinator to learn normal behavior patterns
"""
import sys
import os
import json
from pathlib import Path
from typing import List, Dict
import psycopg2
from psycopg2.extras import execute_values
from urllib.parse import urlparse

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure.cm_client import ContentManagerClient
from config.settings import settings


class HallucinatorTrainer:
    """Train hallucinator with audit log data"""
    
    def __init__(self, db_url: str = None):
        """Initialize trainer with database configuration"""
        db_url = db_url or settings.database.url
        
        # Parse database URL
        parsed = urlparse(db_url)
        self.db_config = {
            'host': parsed.hostname or 'localhost',
            'port': parsed.port or 5432,
            'database': parsed.path.lstrip('/') if parsed.path else 'otcm_audit',
            'user': parsed.username or 'postgres',
            'password': parsed.password or ''
        }
        
        # Initialize CM client with dummy credentials (we only need embedding function)
        try:
            self.cm_client = ContentManagerClient(
                base_url=settings.content_manager.base_url or 'http://localhost',
                username=settings.content_manager.username or 'dummy',
                password=settings.content_manager.password or 'dummy'
            )
        except:
            # If settings not available, create with dummy values
            self.cm_client = ContentManagerClient(
                base_url='http://localhost',
                username='dummy',
                password='dummy'
            )
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            conn = psycopg2.connect(**self.db_config)
            return conn
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return None
    
    def load_audit_logs(self, filepath: str) -> List[Dict]:
        """Load audit logs from JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            results = data.get('Results', [])
            print(f"✓ Loaded {len(results)} audit log entries")
            return results
        except Exception as e:
            print(f"❌ Failed to load audit logs: {e}")
            return []
    
    def convert_logs_to_embeddings(self, logs: List[Dict]) -> List[Dict]:
        """
        Convert audit logs to embeddings
        
        Args:
            logs: List of audit log dictionaries
            
        Returns:
            List of logs with added embedding vectors
        """
        print("\n🔄 Converting logs to embeddings...")
        enriched_logs = []
        
        for i, log in enumerate(logs, 1):
            # Convert log to text representation
            log_text = self._log_to_text(log)
            
            # Generate embedding
            embedding = self.cm_client.convert_to_embedding(log_text)
            
            # Add embedding to log
            log_with_embedding = log.copy()
            log_with_embedding['embedding'] = embedding
            log_with_embedding['log_text'] = log_text
            
            enriched_logs.append(log_with_embedding)
            
            if i % 10 == 0:
                print(f"  Processed {i}/{len(logs)} logs...")
        
        print(f"✓ Generated embeddings for {len(enriched_logs)} logs")
        return enriched_logs
    
    def _log_to_text(self, log: Dict) -> str:
        """Convert log dictionary to text representation"""
        event_desc = log.get('HistoryEventDescription', {}).get('Value', '')
        event_type = log.get('HistoryEventType', {}).get('StringValue', '')
        object_type = log.get('HistoryForObjectType', {}).get('StringValue', '')
        timestamp = log.get('HistoryDoneOn', {}).get('StringValue', '')
        user = log.get('HistoryLoginLocation', {}).get('NameString', 'Unknown')
        is_violation = log.get('HistoryIsSecurityViolation', {}).get('Value', False)
        
        text = f"{event_type} {object_type} by {user} at {timestamp}. "
        if is_violation:
            text += "SECURITY VIOLATION. "
        text += event_desc
        
        return text
    
    def store_in_vector_db(self, logs_with_embeddings: List[Dict]) -> bool:
        """
        Store logs and embeddings in pgvector database
        
        Args:
            logs_with_embeddings: Logs with embedding vectors
            
        Returns:
            True if successful, False otherwise
        """
        print("\n💾 Storing logs in vector database...")
        
        conn = self.connect_db()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Verify table exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'audit_logs'
                )
            """)
            
            if not cursor.fetchone()[0]:
                print("❌ audit_logs table does not exist!")
                print("   Please run: python scripts/init_db.py")
                return False
            
            # Prepare data for insertion
            insert_data = []
            for log in logs_with_embeddings:
                uri = log.get('Uri', 0)
                event_type = log.get('HistoryEventType', {}).get('StringValue', '')
                object_type = log.get('HistoryForObjectType', {}).get('StringValue', '')
                user_name = log.get('HistoryLoginLocation', {}).get('NameString', '')
                timestamp = log.get('HistoryDoneOn', {}).get('StringValue', '')
                is_violation = log.get('HistoryIsSecurityViolation', {}).get('Value', False)
                description = log.get('HistoryEventDescription', {}).get('Value', '')
                embedding = log.get('embedding', [])
                
                insert_data.append((
                    uri,
                    event_type,
                    object_type,
                    user_name,
                    timestamp,
                    is_violation,
                    description,
                    json.dumps(log),
                    embedding
                ))
            
            # Batch insert
            execute_values(
                cursor,
                """
                INSERT INTO audit_logs 
                (uri, event_type, object_type, user_name, timestamp, 
                 is_security_violation, description, log_data, embedding, created_at)
                VALUES %s
                ON CONFLICT DO NOTHING
                """,
                insert_data,
                template="(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::vector, NOW())"
            )
            
            conn.commit()
            print(f"✓ Stored {len(insert_data)} logs in vector database")
            
            # Verify storage
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total_count = cursor.fetchone()[0]
            print(f"  Total logs in database: {total_count}")
            
            # Test vector search capability
            cursor.execute("""
                SELECT COUNT(*) FROM audit_logs WHERE embedding IS NOT NULL
            """)
            vector_count = cursor.fetchone()[0]
            print(f"  Logs with embeddings: {vector_count}")
            
            cursor.close()
            conn.close()
            return True
            
        except Exception as e:
            print(f"❌ Failed to store in database: {e}")
            if 'does not exist' in str(e) or 'relation' in str(e):
                print("\n💡 Tip: Run 'python scripts/init_db.py' first to create the database schema")
            if conn:
                conn.rollback()
                conn.close()
            return False
    
    def create_training_examples(self, logs: List[Dict]) -> List[Dict]:
        """
        Create training examples for hallucinator
        
        Generates examples of:
        1. Normal behavior patterns
        2. Anomalous behavior that needs justification
        3. Known security violations
        
        Returns:
            List of training examples with prompts and expected responses
        """
        print("\n📚 Creating training examples...")
        
        examples = []
        
        # Group logs by user
        user_logs = {}
        for log in logs:
            user = log.get('HistoryLoginLocation', {}).get('NameString', 'Unknown')
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        
        # Create examples for each user
        for user, user_events in user_logs.items():
            # Example 1: Normal behavior pattern
            normal_events = [e for e in user_events if not e.get('HistoryIsSecurityViolation', {}).get('Value', False)]
            if normal_events:
                example = {
                    'type': 'normal_pattern',
                    'user': user,
                    'events': normal_events[:5],  # First 5 normal events
                    'label': 'benign',
                    'justification': f"User {user} exhibits consistent normal behavior within business hours"
                }
                examples.append(example)
            
            # Example 2: Security violations (need justification)
            violations = [e for e in user_events if e.get('HistoryIsSecurityViolation', {}).get('Value', False)]
            if violations:
                example = {
                    'type': 'security_violation',
                    'user': user,
                    'events': violations,
                    'label': 'requires_justification',
                    'justification': 'Hallucinator should attempt to find benign explanation'
                }
                examples.append(example)
            
            # Example 3: Off-hours activity
            off_hours = self._find_off_hours_activity(user_events)
            if off_hours:
                example = {
                    'type': 'off_hours',
                    'user': user,
                    'events': off_hours,
                    'label': 'suspicious_requires_context',
                    'justification': 'Could be legitimate work outside normal hours, deadline, or maintenance'
                }
                examples.append(example)
        
        print(f"✓ Created {len(examples)} training examples")
        
        # Save examples to file
        examples_file = 'hallucinator_training_examples.json'
        with open(examples_file, 'w', encoding='utf-8') as f:
            json.dump(examples, f, indent=4, ensure_ascii=False)
        
        print(f"✓ Saved training examples to: {examples_file}")
        
        return examples
    
    def _find_off_hours_activity(self, events: List[Dict]) -> List[Dict]:
        """Find events that occurred outside normal business hours"""
        off_hours = []
        
        for event in events:
            timestamp_str = event.get('HistoryDoneOn', {}).get('StringValue', '')
            if 'at' in timestamp_str:
                time_part = timestamp_str.split('at')[1].strip()
                hour = int(time_part.split(':')[0])
                
                # Off hours: before 9am or after 5pm
                if hour < 9 or hour > 17:
                    off_hours.append(event)
        
        return off_hours
    
    def generate_summary_report(self, logs: List[Dict], examples: List[Dict]):
        """Generate training summary report"""
        print("\n" + "=" * 60)
        print("📊 HALLUCINATOR TRAINING SUMMARY")
        print("=" * 60)
        
        # Overall statistics
        total_logs = len(logs)
        security_violations = sum(1 for log in logs if log.get('HistoryIsSecurityViolation', {}).get('Value', False))
        
        # Event type distribution
        event_types = {}
        for log in logs:
            et = log.get('HistoryEventType', {}).get('StringValue', 'Unknown')
            event_types[et] = event_types.get(et, 0) + 1
        
        # User statistics
        users = set(log.get('HistoryLoginLocation', {}).get('NameString', 'Unknown') for log in logs)
        
        # Example distribution
        example_types = {}
        for ex in examples:
            et = ex['type']
            example_types[et] = example_types.get(et, 0) + 1
        
        print(f"\n📈 Dataset Statistics:")
        print(f"  Total Logs: {total_logs}")
        print(f"  Security Violations: {security_violations} ({security_violations/total_logs*100:.1f}%)")
        print(f"  Unique Users: {len(users)}")
        print(f"\n📊 Event Type Distribution:")
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type}: {count}")
        
        print(f"\n🎯 Training Examples:")
        print(f"  Total Examples: {len(examples)}")
        for ex_type, count in example_types.items():
            print(f"  {ex_type}: {count}")
        
        print("\n" + "=" * 60)


def main():
    """Main training function"""
    print("🚀 Hallucinator Training Pipeline")
    print("=" * 60)
    
    # Configuration
    data_file = Path(__file__).parent / "generated_audit_logs.json"
    
    if not data_file.exists():
        print(f"❌ Data file not found: {data_file}")
        print("   Please run generate_audit_data.py first")
        return
    
    # Initialize trainer
    trainer = HallucinatorTrainer()
    
    # Step 1: Load audit logs
    logs = trainer.load_audit_logs(str(data_file))
    if not logs:
        return
    
    # Step 2: Convert to embeddings
    logs_with_embeddings = trainer.convert_logs_to_embeddings(logs)
    
    # Step 3: Store in vector database
    success = trainer.store_in_vector_db(logs_with_embeddings)
    if not success:
        print("\n⚠️  Warning: Failed to store in database (continuing anyway)")
    
    # Step 4: Create training examples
    examples = trainer.create_training_examples(logs)
    
    # Step 5: Generate summary report
    trainer.generate_summary_report(logs, examples)
    
    print("\n✅ Hallucinator training completed successfully!")
    print("\n📝 Next steps:")
    print("  1. Review hallucinator_training_examples.json")
    print("  2. Use these patterns to improve defense generation")
    print("  3. Query vector DB for similar historical events")
    print("  4. Fine-tune hallucinator prompts based on patterns")


if __name__ == "__main__":
    main()
