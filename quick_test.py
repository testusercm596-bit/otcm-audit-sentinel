"""
Quick start script for testing the complete system
"""
import sys
import os

sys.path.append(os.path.dirname(__file__))

from main import AuditSentinelOrchestrator
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def quick_test():
    """Run a quick test of the system"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        🧪 OTCM AUDIT SENTINEL - QUICK TEST               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    print("This will run a single iteration to test the complete pipeline.\n")
    
    try:
        # Initialize
        print("1️⃣  Initializing system...")
        orchestrator = AuditSentinelOrchestrator()
        
        # Run once
        print("\n2️⃣  Running analysis...")
        orchestrator.run_once()
        
        # Show results
        print("\n3️⃣  Results:")
        print("="*60)
        for key, value in orchestrator.stats.items():
            print(f"  {key}: {value}")
        print("="*60)
        
        print("\n✅ Quick test completed successfully!")
        print("\nNext steps:")
        print("  - Run 'python main.py' for continuous monitoring")
        print("  - Run 'python run_interactive.py' for interactive mode")
        print("  - Run 'streamlit run src/interface/streamlit_app.py' for UI")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        logger.error("Test failed", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    quick_test()
