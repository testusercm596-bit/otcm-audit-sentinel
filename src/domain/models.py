"""
Domain models for OTCM Audit Sentinel
"""
from sqlalchemy import Column, String, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from pgvector.sqlalchemy import Vector
from datetime import datetime

Base = declarative_base()


class AuditLog(Base):
    """
    Audit log model for storing Content Manager audit events
    with vector embeddings for semantic search
    """
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    event_metadata = Column(JSON, nullable=True)
    embedding = Column(Vector(1536), nullable=True)  # OpenAI ada-002 embedding dimension
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, user_id='{self.user_id}', action='{self.action}', timestamp='{self.timestamp}')>"
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_metadata': self.event_metadata
        }
