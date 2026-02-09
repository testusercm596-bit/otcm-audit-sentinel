"""
Rule Management Models for storing admin-defined security rules
"""
from sqlalchemy import Column, String, DateTime, JSON, Float, Boolean, Integer, Text
from datetime import datetime
from src.domain.models import Base


class SecurityRule(Base):
    """
    Model for storing security rules (both structured and natural language)
    """
    __tablename__ = 'security_rules'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    rule_type = Column(String(50), nullable=False, index=True)  # 'structured' or 'natural_language'
    
    # For natural language rules
    natural_language_rule = Column(Text, nullable=True)
    
    # For structured rules
    condition = Column(String(255), nullable=True)
    operator = Column(String(50), nullable=True)
    value = Column(JSON, nullable=True)
    threshold = Column(Integer, nullable=True)
    
    # Common fields
    description = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.7)
    enabled = Column(Boolean, nullable=False, default=True)
    
    # Metadata
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_triggered = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, nullable=False, default=0)
    
    def __repr__(self):
        return f"<SecurityRule(id={self.id}, name='{self.name}', type='{self.rule_type}')>"
    
    def to_dict(self):
        """Convert model to dictionary for use with SentinelAgent"""
        base_dict = {
            'id': self.id,
            'name': self.name,
            'rule_type': self.rule_type,
            'risk_score': self.risk_score,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if self.rule_type == 'natural_language':
            base_dict['natural_language_rule'] = self.natural_language_rule
        else:  # structured
            base_dict.update({
                'condition': self.condition,
                'operator': self.operator,
                'value': self.value,
                'threshold': self.threshold,
                'description': self.description
            })
        
        return base_dict
    
    def to_full_dict(self):
        """Convert model to complete dictionary including metadata"""
        return {
            'id': self.id,
            'name': self.name,
            'rule_type': self.rule_type,
            'natural_language_rule': self.natural_language_rule,
            'condition': self.condition,
            'operator': self.operator,
            'value': self.value,
            'threshold': self.threshold,
            'description': self.description,
            'risk_score': self.risk_score,
            'enabled': self.enabled,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_triggered': self.last_triggered.isoformat() if self.last_triggered else None,
            'trigger_count': self.trigger_count
        }
