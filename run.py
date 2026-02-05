"""
Quick start script for OTCM Audit Sentinel
"""
import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def main():
    """Main entry point"""
    print("=" * 60)
    print("🛡️  OTCM Audit Sentinel")
    print("=" * 60)
    print("\nChoose an option:")
    print("1. Launch Streamlit UI")
    print("2. Start API Server")
    print("3. Run Tests")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == "1":
        print("\n🚀 Launching Streamlit UI...")
        os.system("streamlit run src/interface/streamlit_app.py")
    elif choice == "2":
        print("\n🚀 Starting API Server...")
        os.system("uvicorn src.interface.api:app --reload")
    elif choice == "3":
        print("\n🧪 Running Tests...")
        os.system("pytest tests/ -v")
    elif choice == "4":
        print("\n👋 Goodbye!")
        sys.exit(0)
    else:
        print("\n❌ Invalid choice. Please try again.")
        main()

if __name__ == "__main__":
    main()
