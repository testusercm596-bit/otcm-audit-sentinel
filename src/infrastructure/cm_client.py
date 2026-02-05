"""
Content Manager Client for fetching audit logs and processing them
"""
import sys
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import random

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class ContentManagerClient:
    """
    Client for fetching audit logs from OpenText Content Manager
    and converting them to embeddings for vector search
    """
    
    def __init__(self, base_url: str, username: str, password: str, domain: Optional[str] = None):
        """
        Initialize Content Manager client
        
        Args:
            base_url: Content Manager base URL
            username: NTLM username
            password: NTLM password
            domain: Optional Windows domain
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.domain = domain
    
    def fetch_recent_logs(self, last_checked_time: datetime) -> List[Dict]:
        """
        Fetch recent audit logs from Content Manager since the last checked time
        
        Args:
            last_checked_time: Timestamp of last fetch
            
        Returns:
            List of audit log dictionaries
        
        Note:
            This is a MOCK implementation. Replace with actual API calls when available.
        """
        # Mock data generation
        mock_logs = []
        
        # Generate mock logs for demonstration
        actors = ["john.doe", "jane.smith", "admin_user", "bob.johnson", "alice.williams"]
        events = ["READ", "WRITE", "DELETE", "UPDATE", "MOVE", "COPY", "SHARE", "DOWNLOAD"]
        record_types = ["Document", "Folder", "Email", "Contract", "Report", "Spreadsheet"]
        statuses = ["SUCCESS", "FAILED", "PARTIAL"]
        
        # Generate 10-20 mock logs
        num_logs = random.randint(10, 20)
        
        for i in range(num_logs):
            # Generate timestamp between last_checked_time and now
            time_diff = datetime.utcnow() - last_checked_time
            random_seconds = random.randint(0, int(time_diff.total_seconds()))
            log_time = last_checked_time + timedelta(seconds=random_seconds)
            
            log = {
                "id": f"LOG_{datetime.utcnow().timestamp()}_{i}",
                "actor": random.choice(actors),
                "event": random.choice(events),
                "record_type": random.choice(record_types),
                "timestamp": log_time.isoformat(),
                "status": random.choice(statuses),
                "record_id": f"REC_{random.randint(1000, 9999)}",
                "record_title": f"Sample {random.choice(record_types)} {random.randint(1, 100)}",
                "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "details": {
                    "action_performed": f"{random.choice(events)} operation on {random.choice(record_types)}",
                    "duration_ms": random.randint(50, 5000),
                    "data_size_kb": random.randint(1, 10000) if random.random() > 0.3 else None
                }
            }
            
            mock_logs.append(log)
        
        # Sort by timestamp
        mock_logs.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return mock_logs
    
    def convert_to_embedding(self, log_text: str) -> List[float]:
        """
        Convert log text to vector embedding for similarity search
        
        Args:
            log_text: Text representation of the log entry
            
        Returns:
            List of floats representing the embedding vector (1536 dimensions for OpenAI)
        
        Note:
            This is a PLACEHOLDER implementation. In production, this should:
            1. Call OpenAI's text-embedding-ada-002 model
            2. Or use a local embedding model
            3. Handle rate limiting and errors
        
        Example production implementation:
            import openai
            response = openai.Embedding.create(
                input=log_text,
                model="text-embedding-ada-002"
            )
            return response['data'][0]['embedding']
        """
        # MOCK: Return a random 1536-dimensional vector
        # In production, replace this with actual embedding API call
        
        # For now, generate a deterministic random vector based on text hash
        # This ensures same text always gets same embedding
        import hashlib
        text_hash = int(hashlib.md5(log_text.encode()).hexdigest(), 16)
        random.seed(text_hash)
        
        # Generate 1536-dimensional vector (OpenAI ada-002 embedding size)
        embedding = [random.uniform(-1, 1) for _ in range(1536)]
        
        # Reset random seed
        random.seed()
        
        return embedding
    
    def log_to_text(self, log: Dict) -> str:
        """
        Convert a log dictionary to a text representation for embedding
        
        Args:
            log: Audit log dictionary
            
        Returns:
            String representation of the log
        """
        text_parts = [
            f"Actor: {log.get('actor', 'unknown')}",
            f"Event: {log.get('event', 'unknown')}",
            f"Record Type: {log.get('record_type', 'unknown')}",
            f"Status: {log.get('status', 'unknown')}",
            f"Record: {log.get('record_title', 'unknown')}",
            f"Time: {log.get('timestamp', 'unknown')}"
        ]
        
        # Add details if available
        if 'details' in log and log['details']:
            details = log['details']
            if 'action_performed' in details:
                text_parts.append(f"Action: {details['action_performed']}")
        
        return " | ".join(text_parts)
    
    def fetch_and_embed_logs(self, last_checked_time: datetime) -> List[Dict]:
        """
        Fetch logs and generate embeddings for each
        
        Args:
            last_checked_time: Timestamp of last fetch
            
        Returns:
            List of log dictionaries with 'embedding' field added
        """
        logs = self.fetch_recent_logs(last_checked_time)
        
        for log in logs:
            log_text = self.log_to_text(log)
            log['embedding'] = self.convert_to_embedding(log_text)
            log['log_text'] = log_text  # Store the text representation
        
        return logs
    
    def test_connection(self) -> bool:
        """
        Test the connection to Content Manager
        
        Returns:
            True if connection is successful, False otherwise
        
        Note:
            MOCK implementation - always returns True
        """
        # TODO: Implement actual connection test when API is available
        # This could try to authenticate and fetch a single record
        return True


def create_client_from_settings():
    """
    Create a ContentManagerClient using settings from config
    
    Returns:
        ContentManagerClient instance
    """
    from src.config.settings import settings
    
    return ContentManagerClient(
        base_url=settings.content_manager.base_url,
        username=settings.content_manager.username,
        password=settings.content_manager.password,
        domain=settings.content_manager.domain
    )
