"""
Example script demonstrating how to use the Content Manager Client
"""
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure.cm_client import ContentManagerClient, create_client_from_settings


def example_basic_usage():
    """Example: Basic usage of ContentManagerClient"""
    print("=" * 60)
    print("Example 1: Basic Usage")
    print("=" * 60)
    
    # Create client
    client = ContentManagerClient(
        base_url="https://cm.example.com",
        username="demo_user",
        password="demo_pass",
        domain="COMPANY"
    )
    
    # Fetch logs from the last hour
    last_checked = datetime.utcnow() - timedelta(hours=1)
    logs = client.fetch_recent_logs(last_checked)
    
    print(f"\n✅ Fetched {len(logs)} audit logs\n")
    
    # Display first 3 logs
    for i, log in enumerate(logs[:3], 1):
        print(f"Log {i}:")
        print(f"  Actor: {log['actor']}")
        print(f"  Event: {log['event']}")
        print(f"  Record Type: {log['record_type']}")
        print(f"  Status: {log['status']}")
        print(f"  Time: {log['timestamp']}")
        print()


def example_with_embeddings():
    """Example: Fetch logs with embeddings"""
    print("=" * 60)
    print("Example 2: Fetch Logs with Embeddings")
    print("=" * 60)
    
    client = ContentManagerClient(
        base_url="https://cm.example.com",
        username="demo_user",
        password="demo_pass"
    )
    
    # Fetch logs with embeddings
    last_checked = datetime.utcnow() - timedelta(hours=2)
    logs = client.fetch_and_embed_logs(last_checked)
    
    print(f"\n✅ Fetched {len(logs)} logs with embeddings\n")
    
    # Show first log with embedding info
    log = logs[0]
    print(f"Sample Log:")
    print(f"  Text: {log['log_text']}")
    print(f"  Embedding dimensions: {len(log['embedding'])}")
    print(f"  First 5 embedding values: {log['embedding'][:5]}")
    print()


def example_convert_text_to_embedding():
    """Example: Convert custom text to embedding"""
    print("=" * 60)
    print("Example 3: Convert Text to Embedding")
    print("=" * 60)
    
    client = ContentManagerClient(
        base_url="https://cm.example.com",
        username="demo_user",
        password="demo_pass"
    )
    
    # Custom log texts
    log_texts = [
        "User admin performed DELETE on Document",
        "User john.doe performed READ on Email",
        "User jane.smith performed UPDATE on Contract"
    ]
    
    print("\n📝 Converting texts to embeddings:\n")
    
    for text in log_texts:
        embedding = client.convert_to_embedding(text)
        print(f"Text: {text}")
        print(f"  → Embedding: {len(embedding)} dimensions")
        print()


def example_using_settings():
    """Example: Create client from settings"""
    print("=" * 60)
    print("Example 4: Create Client from Settings")
    print("=" * 60)
    
    # This would use values from .env file via settings.py
    # Uncomment when .env is properly configured
    
    # client = create_client_from_settings()
    # print(f"\n✅ Client created from settings")
    # print(f"  Base URL: {client.base_url}")
    # print(f"  Username: {client.username}")
    # print(f"  Domain: {client.domain}")
    
    print("\n⚠️  Skipped - requires configured .env file")
    print()


def main():
    """Run all examples"""
    print("\n🛡️  Content Manager Client Examples\n")
    
    try:
        example_basic_usage()
        example_with_embeddings()
        example_convert_text_to_embedding()
        example_using_settings()
        
        print("=" * 60)
        print("✅ All examples completed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
