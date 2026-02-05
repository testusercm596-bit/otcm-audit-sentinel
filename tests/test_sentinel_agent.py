"""
Unit tests for Sentinel Agent
"""
import pytest
from datetime import datetime
from src.domain.entities import AuditRecord, AuditStatus
from src.application.sentinel_agent import SentinelAgent


class TestSentinelAgent:
    """Test suite for Sentinel Agent"""
    
    @pytest.fixture
    def sentinel_agent(self):
        """Create a Sentinel agent instance for testing"""
        # Use a test API key or mock
        return SentinelAgent(openai_api_key="test_key")
    
    @pytest.fixture
    def sample_audit_records(self):
        """Create sample audit records for testing"""
        return [
            AuditRecord(
                id="1",
                document_id="DOC001",
                timestamp=datetime.now(),
                user_id="user123",
                action="READ",
                status=AuditStatus.COMPLETED,
                metadata={}
            ),
            AuditRecord(
                id="2",
                document_id="DOC002",
                timestamp=datetime.now(),
                user_id="user456",
                action="DELETE",
                status=AuditStatus.COMPLETED,
                metadata={}
            )
        ]
    
    def test_prepare_audit_summary(self, sentinel_agent, sample_audit_records):
        """Test audit summary preparation"""
        summary = sentinel_agent._prepare_audit_summary(sample_audit_records)
        assert len(summary) > 0
        assert "user123" in summary
        assert "READ" in summary
    
    def test_analyze_empty_logs(self, sentinel_agent):
        """Test analysis with empty audit logs"""
        findings = sentinel_agent.analyze_audit_logs([])
        assert isinstance(findings, list)
    
    # Add more tests as needed
