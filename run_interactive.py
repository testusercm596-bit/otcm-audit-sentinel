"""
Interactive CLI for running OTCM Audit Sentinel
"""
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(__file__))

from main import AuditSentinelOrchestrator
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_single_check():
    """Run a single check iteration"""
    print("\n🔍 Running single check...\n")
    orchestrator = AuditSentinelOrchestrator()
    orchestrator.run_once()
    print("\n✅ Single check completed!")
    print("\nStatistics:")
    for key, value in orchestrator.stats.items():
        print(f"  {key}: {value}")


def run_continuous():
    """Run continuous monitoring"""
    interval = input("\nEnter check interval in seconds (default: 60): ").strip()
    interval = int(interval) if interval else 60
    
    orchestrator = AuditSentinelOrchestrator()
    orchestrator.run_continuous(interval_seconds=interval)


def view_alerts():
    """View recent alerts"""
    from src.infrastructure.database import db
    from src.infrastructure.alert_repository import AlertResultRepository
    
    print("\n📋 Recent Alerts\n")
    
    db.connect()
    session = db.get_session()
    alert_repo = AlertResultRepository(session)
    
    try:
        alerts = alert_repo.get_active_alerts(limit=10)
        
        if not alerts:
            print("No active alerts found.")
        else:
            for i, alert in enumerate(alerts, 1):
                print(f"{i}. [{alert.final_status.upper()}] {alert.user_id} - {alert.event_type}")
                print(f"   Risk: {alert.risk_score:.2f} | Defense: {alert.defense_confidence:.2f if alert.defense_confidence else 'N/A'}")
                print(f"   Reason: {alert.alert_reason[:80]}...")
                print()
    finally:
        session.close()
        db.close()


def main_menu():
    """Display main menu"""
    while True:
        print("\n" + "="*60)
        print("🛡️  OTCM Audit Sentinel - Interactive Mode")
        print("="*60)
        print("\nOptions:")
        print("  1. Run single check")
        print("  2. Run continuous monitoring")
        print("  3. View recent alerts")
        print("  4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            try:
                run_single_check()
            except Exception as e:
                logger.error(f"Error: {e}", exc_info=True)
                print(f"\n❌ Error: {e}")
        
        elif choice == "2":
            try:
                run_continuous()
            except Exception as e:
                logger.error(f"Error: {e}", exc_info=True)
                print(f"\n❌ Error: {e}")
        
        elif choice == "3":
            try:
                view_alerts()
            except Exception as e:
                logger.error(f"Error: {e}", exc_info=True)
                print(f"\n❌ Error: {e}")
        
        elif choice == "4":
            print("\n👋 Goodbye!")
            break
        
        else:
            print("\n❌ Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
