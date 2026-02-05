"""
Repository pattern for AuditLog operations
"""
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc

from src.domain.models import AuditLog


class AuditLogRepository:
    """Repository for AuditLog database operations"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, user_id: str, action: str, metadata: dict = None, embedding: List[float] = None) -> AuditLog:
        """Create a new audit log entry"""
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            timestamp=datetime.utcnow(),
            metadata=metadata,
            embedding=embedding
        )
        self.session.add(audit_log)
        self.session.commit()
        self.session.refresh(audit_log)
        return audit_log
    
    def get_by_id(self, log_id: int) -> Optional[AuditLog]:
        """Get audit log by ID"""
        return self.session.query(AuditLog).filter(AuditLog.id == log_id).first()
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        """Get all audit logs with pagination"""
        return self.session.query(AuditLog)\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .offset(offset)\
            .all()
    
    def get_by_user(self, user_id: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for a specific user"""
        return self.session.query(AuditLog)\
            .filter(AuditLog.user_id == user_id)\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .all()
    
    def get_by_action(self, action: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for a specific action"""
        return self.session.query(AuditLog)\
            .filter(AuditLog.action == action)\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .all()
    
    def get_by_date_range(self, start_date: datetime, end_date: datetime) -> List[AuditLog]:
        """Get audit logs within a date range"""
        return self.session.query(AuditLog)\
            .filter(AuditLog.timestamp >= start_date)\
            .filter(AuditLog.timestamp <= end_date)\
            .order_by(desc(AuditLog.timestamp))\
            .all()
    
    def search_by_embedding(self, query_embedding: List[float], limit: int = 10) -> List[AuditLog]:
        """
        Perform vector similarity search
        Returns audit logs most similar to the query embedding
        """
        # Using pgvector's <-> operator for L2 distance
        return self.session.query(AuditLog)\
            .filter(AuditLog.embedding.isnot(None))\
            .order_by(AuditLog.embedding.l2_distance(query_embedding))\
            .limit(limit)\
            .all()
    
    def delete(self, log_id: int) -> bool:
        """Delete an audit log entry"""
        audit_log = self.get_by_id(log_id)
        if audit_log:
            self.session.delete(audit_log)
            self.session.commit()
            return True
        return False
