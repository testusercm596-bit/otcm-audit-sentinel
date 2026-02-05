"""
Alert Result Model for storing security analysis results
"""
from sqlalchemy import Column, String, DateTime, JSON, Float, Boolean, Integer, Text
from datetime import datetime
from src.domain.models import Base


class AlertResult(Base):
    """
    Model for storing security alert analysis results
    combining Sentinel detection and Hallucinator defense
    """
    __tablename__ = 'alert_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_log_id = Column(Integer, nullable=True)  # Reference to audit_log
    user_id = Column(String(255), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Sentinel Alert Info
    is_alert = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    alert_reason = Column(Text, nullable=True)
    rule_triggered = Column(String(255), nullable=True)
    distance_score = Column(Float, nullable=True)
    
    # Hallucinator Defense Info
    defense_generated = Column(Boolean, nullable=False, default=False)
    defense_justification = Column(Text, nullable=True)
    defense_confidence = Column(Float, nullable=True)
    supporting_evidence = Column(JSON, nullable=True)
    risk_mitigation = Column(Text, nullable=True)
    
    # Final Decision
    final_status = Column(String(50), nullable=False, default='pending')  # pending, dismissed, escalated
    dismissed = Column(Boolean, nullable=False, default=False)
    
    # Metadata
    event_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<AlertResult(id={self.id}, user_id='{self.user_id}', status='{self.final_status}')>"
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'audit_log_id': self.audit_log_id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_alert': self.is_alert,
            'risk_score': self.risk_score,
            'alert_reason': self.alert_reason,
            'defense_confidence': self.defense_confidence,
            'final_status': self.final_status,
            'dismissed': self.dismissed
        }
