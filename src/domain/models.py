"""
Domain models for OTCM Audit Sentinel
"""
from sqlalchemy import Column, String, DateTime, JSON, Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from pgvector.sqlalchemy import Vector
from datetime import datetime

Base = declarative_base()


class AuditLog(Base):
    """
    Audit log model for storing Content Manager audit events
    with vector embeddings for semantic search
    
    Compatible with OpenText Content Manager audit log structure
    """
    __tablename__ = 'audit_logs'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # OTCM-specific fields
    uri = Column(Integer, nullable=True, index=True)  # OTCM Uri field
    event_type = Column(String(100), nullable=True, index=True)  # e.g., 'Added', 'Deleted', 'Modified'
    object_type = Column(String(100), nullable=True, index=True)  # e.g., 'Record', 'Document', 'Location'
    user_name = Column(String(255), nullable=True, index=True)  # User who performed the action
    timestamp = Column(String(50), nullable=True, index=True)  # String timestamp from OTCM
    is_security_violation = Column(Boolean, default=False, index=True)  # Security flag
    description = Column(Text, nullable=True)  # Full event description
    
    # JSON storage for full log data
    log_data = Column(JSON, nullable=True)  # Complete OTCM audit log entry
    
    # Legacy fields for backward compatibility
    user_id = Column(String(255), nullable=True, index=True)  # Alias for user_name
    action = Column(String(100), nullable=True, index=True)  # Alias for event_type
    event_metadata = Column(JSON, nullable=True)  # Additional metadata
    
    # Vector embedding for semantic search
    embedding = Column(Vector(1536), nullable=True)  # OpenAI ada-002 embedding dimension
    
    # Audit fields
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, uri={self.uri}, user='{self.user_name}', event='{self.event_type}', object='{self.object_type}')>"
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'uri': self.uri,
            'event_type': self.event_type,
            'object_type': self.object_type,
            'user_name': self.user_name,
            'timestamp': self.timestamp,
            'is_security_violation': self.is_security_violation,
            'description': self.description,
            'user_id': self.user_id,
            'action': self.action,
            'event_metadata': self.event_metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
