"""
Unit tests for database models and repositories
"""
import pytest
from datetime import datetime
from src.domain.models import AuditLog


class TestAuditLogModel:
    """Test suite for AuditLog model"""
    
    def test_audit_log_creation(self):
        """Test AuditLog model instantiation"""
        audit_log = AuditLog(
            user_id="user123",
            action="READ",
            timestamp=datetime.utcnow(),
            event_metadata={"document_id": "DOC001"}
        )
        
        assert audit_log.user_id == "user123"
        assert audit_log.action == "READ"
        assert audit_log.event_metadata["document_id"] == "DOC001"
    
    def test_audit_log_to_dict(self):
        """Test AuditLog to_dict conversion"""
        timestamp = datetime.utcnow()
        audit_log = AuditLog(
            id=1,
            user_id="user123",
            action="DELETE",
            timestamp=timestamp,
            event_metadata={"reason": "test"}
        )
        
        result = audit_log.to_dict()
        
        assert result["id"] == 1
        assert result["user_id"] == "user123"
        assert result["action"] == "DELETE"
        assert result["event_metadata"]["reason"] == "test"
    
    def test_audit_log_repr(self):
        """Test AuditLog string representation"""
        timestamp = datetime.utcnow()
        audit_log = AuditLog(
            id=1,
            user_id="user123",
            action="UPDATE",
            timestamp=timestamp
        )
        
        repr_str = repr(audit_log)
        assert "AuditLog" in repr_str
        assert "user123" in repr_str
        assert "UPDATE" in repr_str
