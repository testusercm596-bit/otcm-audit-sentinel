"""
Unit tests for Content Manager Client
"""
import pytest
from datetime import datetime, timedelta
from src.infrastructure.cm_client import ContentManagerClient


class TestContentManagerClient:
    """Test suite for ContentManagerClient"""
    
    @pytest.fixture
    def cm_client(self):
        """Create a test Content Manager client"""
        return ContentManagerClient(
            base_url="https://test.example.com",
            username="test_user",
            password="test_password",
            domain="TEST_DOMAIN"
        )
    
    def test_client_initialization(self, cm_client):
        """Test client initialization"""
        assert cm_client.base_url == "https://test.example.com"
        assert cm_client.username == "test_user"
        assert cm_client.domain == "TEST_DOMAIN"
    
    def test_fetch_recent_logs(self, cm_client):
        """Test fetching recent logs"""
        last_checked = datetime.utcnow() - timedelta(hours=1)
        logs = cm_client.fetch_recent_logs(last_checked)
        
        assert isinstance(logs, list)
        assert len(logs) > 0
        
        # Check log structure
        log = logs[0]
        assert "actor" in log
        assert "event" in log
        assert "record_type" in log
        assert "timestamp" in log
        assert "status" in log
    
    def test_convert_to_embedding(self, cm_client):
        """Test embedding conversion"""
        log_text = "Actor: john.doe | Event: READ | Record Type: Document"
        embedding = cm_client.convert_to_embedding(log_text)
        
        assert isinstance(embedding, list)
        assert len(embedding) == 1536  # OpenAI embedding dimension
        assert all(isinstance(x, float) for x in embedding)
    
    def test_embedding_deterministic(self, cm_client):
        """Test that same text produces same embedding"""
        log_text = "Actor: john.doe | Event: READ | Record Type: Document"
        
        embedding1 = cm_client.convert_to_embedding(log_text)
        embedding2 = cm_client.convert_to_embedding(log_text)
        
        assert embedding1 == embedding2
    
    def test_log_to_text(self, cm_client):
        """Test log to text conversion"""
        log = {
            "actor": "john.doe",
            "event": "READ",
            "record_type": "Document",
            "status": "SUCCESS",
            "record_title": "Test Document",
            "timestamp": "2026-02-05T10:00:00"
        }
        
        text = cm_client.log_to_text(log)
        
        assert "john.doe" in text
        assert "READ" in text
        assert "Document" in text
        assert "SUCCESS" in text
    
    def test_fetch_and_embed_logs(self, cm_client):
        """Test fetching logs with embeddings"""
        last_checked = datetime.utcnow() - timedelta(hours=1)
        logs = cm_client.fetch_and_embed_logs(last_checked)
        
        assert len(logs) > 0
        
        # Check that embeddings were added
        log = logs[0]
        assert "embedding" in log
        assert "log_text" in log
        assert len(log["embedding"]) == 1536
    
    def test_connection_test(self, cm_client):
        """Test connection test method"""
        # Mock always returns True
        result = cm_client.test_connection()
        assert result is True
