"""
Database Update Script - Add Security Rules Table
Run this to update your database with the new security_rules table
"""
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure.database import db
from config.settings import settings
from src.domain.rule_models import SecurityRule  # Import to create table

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Update database with new security_rules table"""
    logger.info("Starting database update...")
    
    # Validate settings
    if not settings.validate():
        logger.error("Invalid configuration. Please check your .env file")
        return False
    
    try:
        # Connect to database
        logger.info("Connecting to database...")
        db.connect()
        
        # Create security_rules table
        logger.info("Creating security_rules table...")
        db.init_db()  # This will create all tables including security_rules
        
        logger.info("✅ Database update completed successfully!")
        logger.info("   New table 'security_rules' is ready for use")
        
        # Create some example rules
        create_example = input("\nWould you like to create example security rules? (y/n): ").strip().lower()
        
        if create_example == 'y':
            from src.infrastructure.rule_repository import RuleRepository
            rule_repo = RuleRepository()
            
            logger.info("\nCreating example rules...")
            
            # Example natural language rules
            examples = [
                {
                    "name": "After Hours Access",
                    "nl_rule": "Alert if user accesses sensitive documents between 10 PM and 6 AM",
                    "risk_score": 0.75
                },
                {
                    "name": "Bulk File Download",
                    "nl_rule": "Trigger alert when user downloads more than 50 files in one hour",
                    "risk_score": 0.8
                },
                {
                    "name": "Failed Login Attempts",
                    "condition": "event_type",
                    "operator": "==",
                    "value": "LOGIN_FAILED",
                    "threshold": 5,
                    "risk_score": 0.85,
                    "description": "Too many failed login attempts"
                }
            ]
            
            for example in examples:
                try:
                    if "nl_rule" in example:
                        rule = rule_repo.create_natural_language_rule(
                            name=example["name"],
                            nl_rule=example["nl_rule"],
                            risk_score=example["risk_score"],
                            created_by="system"
                        )
                        logger.info(f"  ✓ Created NL rule: {rule.name}")
                    else:
                        rule = rule_repo.create_structured_rule(
                            name=example["name"],
                            condition=example["condition"],
                            operator=example["operator"],
                            value=example["value"],
                            threshold=example.get("threshold"),
                            description=example.get("description"),
                            risk_score=example["risk_score"],
                            created_by="system"
                        )
                        logger.info(f"  ✓ Created structured rule: {rule.name}")
                except Exception as e:
                    logger.warning(f"  ✗ Could not create rule '{example['name']}': {e}")
            
            logger.info("\n✅ Example rules created!")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Database update failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        db.close()


if __name__ == "__main__":
    print("=" * 80)
    print("OTCM Audit Sentinel - Database Update")
    print("Adding Security Rules Table")
    print("=" * 80)
    print()
    
    success = main()
    
    if success:
        print("\n" + "=" * 80)
        print("✅ Database update completed successfully!")
        print("=" * 80)
        print("\nNext steps:")
        print("1. Start the Streamlit UI: streamlit run src/interface/streamlit_app.py")
        print("2. Navigate to 'Security Rules' page")
        print("3. Create your first natural language security rule!")
        print()
    else:
        print("\n" + "=" * 80)
        print("❌ Database update failed. Please check the logs above.")
        print("=" * 80)
