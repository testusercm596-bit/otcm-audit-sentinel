"""
Alert Result Repository for database operations
"""
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc

from src.domain.alert_models import AlertResult


class AlertResultRepository:
    """Repository for AlertResult database operations"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, **kwargs) -> AlertResult:
        """Create a new alert result entry"""
        alert_result = AlertResult(**kwargs)
        self.session.add(alert_result)
        self.session.commit()
        self.session.refresh(alert_result)
        return alert_result
    
    def get_by_id(self, result_id: int) -> Optional[AlertResult]:
        """Get alert result by ID"""
        return self.session.query(AlertResult).filter(AlertResult.id == result_id).first()
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[AlertResult]:
        """Get all alert results with pagination"""
        return self.session.query(AlertResult)\
            .order_by(desc(AlertResult.timestamp))\
            .limit(limit)\
            .offset(offset)\
            .all()
    
    def get_by_user(self, user_id: str, limit: int = 100) -> List[AlertResult]:
        """Get alert results for a specific user"""
        return self.session.query(AlertResult)\
            .filter(AlertResult.user_id == user_id)\
            .order_by(desc(AlertResult.timestamp))\
            .limit(limit)\
            .all()
    
    def get_active_alerts(self, limit: int = 100) -> List[AlertResult]:
        """Get active (not dismissed) alerts"""
        return self.session.query(AlertResult)\
            .filter(AlertResult.is_alert == True)\
            .filter(AlertResult.dismissed == False)\
            .order_by(desc(AlertResult.risk_score))\
            .limit(limit)\
            .all()
    
    def get_escalated_alerts(self, limit: int = 100) -> List[AlertResult]:
        """Get escalated alerts requiring investigation"""
        return self.session.query(AlertResult)\
            .filter(AlertResult.final_status == 'escalated')\
            .order_by(desc(AlertResult.timestamp))\
            .limit(limit)\
            .all()
    
    def update_status(self, result_id: int, status: str, dismissed: bool = False) -> Optional[AlertResult]:
        """Update alert result status"""
        result = self.get_by_id(result_id)
        if result:
            result.final_status = status
            result.dismissed = dismissed
            self.session.commit()
            self.session.refresh(result)
        return result
