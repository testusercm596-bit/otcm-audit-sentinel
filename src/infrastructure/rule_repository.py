"""
Repository for managing security rules in the database
"""
import sys
import os
from typing import List, Optional, Dict
from datetime import datetime
from sqlalchemy import desc

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.domain.rule_models import SecurityRule
from src.infrastructure.database import db


class RuleRepository:
    """Repository for CRUD operations on security rules"""
    
    def __init__(self):
        """Initialize repository"""
        self.session = None
    
    def create_natural_language_rule(self, name: str, nl_rule: str, risk_score: float = 0.7,
                                    created_by: Optional[str] = None) -> SecurityRule:
        """
        Create a new natural language rule
        
        Args:
            name: Rule name
            nl_rule: Natural language description of the rule
            risk_score: Risk score if triggered (0.0 to 1.0)
            created_by: User who created the rule
            
        Returns:
            Created SecurityRule object
        """
        rule = SecurityRule(
            name=name,
            rule_type='natural_language',
            natural_language_rule=nl_rule,
            risk_score=risk_score,
            enabled=True,
            created_by=created_by,
            created_at=datetime.utcnow()
        )
        
        session = db.get_session()
        try:
            session.add(rule)
            session.commit()
            session.refresh(rule)
            return rule
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def create_structured_rule(self, name: str, condition: str, operator: str, 
                              value: any, risk_score: float = 0.7,
                              threshold: Optional[int] = None,
                              description: Optional[str] = None,
                              created_by: Optional[str] = None) -> SecurityRule:
        """
        Create a new structured rule
        
        Args:
            name: Rule name
            condition: Field to check
            operator: Comparison operator
            value: Value to compare against
            risk_score: Risk score if triggered
            threshold: Optional threshold for counting
            description: Rule description
            created_by: User who created the rule
            
        Returns:
            Created SecurityRule object
        """
        rule = SecurityRule(
            name=name,
            rule_type='structured',
            condition=condition,
            operator=operator,
            value=value,
            threshold=threshold,
            description=description,
            risk_score=risk_score,
            enabled=True,
            created_by=created_by,
            created_at=datetime.utcnow()
        )
        
        session = db.get_session()
        try:
            session.add(rule)
            session.commit()
            session.refresh(rule)
            return rule
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_rule_by_id(self, rule_id: int) -> Optional[SecurityRule]:
        """Get a rule by ID"""
        session = db.get_session()
        try:
            return session.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
        finally:
            session.close()
    
    def get_rule_by_name(self, name: str) -> Optional[SecurityRule]:
        """Get a rule by name"""
        session = db.get_session()
        try:
            return session.query(SecurityRule).filter(SecurityRule.name == name).first()
        finally:
            session.close()
    
    def get_all_rules(self, enabled_only: bool = False, rule_type: Optional[str] = None) -> List[SecurityRule]:
        """
        Get all rules with optional filtering
        
        Args:
            enabled_only: If True, only return enabled rules
            rule_type: Filter by 'structured' or 'natural_language'
            
        Returns:
            List of SecurityRule objects
        """
        session = db.get_session()
        try:
            query = session.query(SecurityRule)
            
            if enabled_only:
                query = query.filter(SecurityRule.enabled == True)
            
            if rule_type:
                query = query.filter(SecurityRule.rule_type == rule_type)
            
            return query.order_by(desc(SecurityRule.created_at)).all()
        finally:
            session.close()
    
    def get_rules_dict_for_sentinel(self, enabled_only: bool = True) -> List[Dict]:
        """
        Get rules formatted for SentinelAgent
        
        Args:
            enabled_only: If True, only return enabled rules
            
        Returns:
            List of rule dictionaries
        """
        rules = self.get_all_rules(enabled_only=enabled_only)
        return [rule.to_dict() for rule in rules]
    
    def update_rule(self, rule_id: int, updates: Dict) -> Optional[SecurityRule]:
        """
        Update a rule
        
        Args:
            rule_id: ID of rule to update
            updates: Dictionary of fields to update
            
        Returns:
            Updated SecurityRule object or None if not found
        """
        session = db.get_session()
        try:
            rule = session.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
            
            if rule:
                for key, value in updates.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                
                rule.updated_at = datetime.utcnow()
                session.commit()
                session.refresh(rule)
            
            return rule
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def enable_rule(self, rule_id: int) -> bool:
        """Enable a rule"""
        return self.update_rule(rule_id, {'enabled': True}) is not None
    
    def disable_rule(self, rule_id: int) -> bool:
        """Disable a rule"""
        return self.update_rule(rule_id, {'enabled': False}) is not None
    
    def delete_rule(self, rule_id: int) -> bool:
        """
        Delete a rule
        
        Args:
            rule_id: ID of rule to delete
            
        Returns:
            True if deleted, False if not found
        """
        session = db.get_session()
        try:
            rule = session.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
            
            if rule:
                session.delete(rule)
                session.commit()
                return True
            
            return False
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def increment_trigger_count(self, rule_id: int):
        """Increment the trigger count and update last triggered time"""
        session = db.get_session()
        try:
            rule = session.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
            
            if rule:
                rule.trigger_count += 1
                rule.last_triggered = datetime.utcnow()
                session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_rule_statistics(self) -> Dict:
        """
        Get statistics about rules
        
        Returns:
            Dictionary with rule statistics
        """
        session = db.get_session()
        try:
            total = session.query(SecurityRule).count()
            enabled = session.query(SecurityRule).filter(SecurityRule.enabled == True).count()
            natural_language = session.query(SecurityRule).filter(SecurityRule.rule_type == 'natural_language').count()
            structured = session.query(SecurityRule).filter(SecurityRule.rule_type == 'structured').count()
            
            return {
                'total_rules': total,
                'enabled_rules': enabled,
                'disabled_rules': total - enabled,
                'natural_language_rules': natural_language,
                'structured_rules': structured
            }
        finally:
            session.close()
