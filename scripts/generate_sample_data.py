"""
Demo script to populate the database with sample data for testing the Streamlit app
"""
import sys
import os
from datetime import datetime, timedelta
import random

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure.database import db
from src.infrastructure.repositories import AuditLogRepository
from src.infrastructure.alert_repository import AlertResultRepository
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_sample_data():
    """Generate sample audit logs and alerts for demonstration"""
    
    logger.info("Connecting to database...")
    db.connect()
    
    session = db.get_session()
    audit_repo = AuditLogRepository(session)
    alert_repo = AlertResultRepository(session)
    
    try:
        logger.info("Generating sample data...")
        
        users = ["john.doe", "jane.smith", "bob.johnson", "alice.williams", "charlie.brown"]
        events = ["READ", "WRITE", "DELETE", "UPDATE", "MOVE", "COPY"]
        
        # Generate 50 normal events
        for i in range(50):
            timestamp = datetime.utcnow() - timedelta(hours=random.randint(0, 24))
            user = random.choice(users)
            event = random.choice(["READ", "WRITE", "UPDATE"])
            
            # Create audit log
            audit_log = audit_repo.create(
                user_id=user,
                action=event,
                metadata={
                    'record_type': 'Document',
                    'record_title': f'Sample_Document_{i}.pdf'
                }
            )
            
            # Create normal alert result (not an alert)
            alert_repo.create(
                audit_log_id=audit_log.id,
                user_id=user,
                event_type=event,
                timestamp=timestamp,
                is_alert=False,
                risk_score=0.0,
                alert_reason="Normal activity",
                final_status='normal',
                dismissed=False
            )
        
        logger.info("Generated 50 normal events")
        
        # Generate 10 alerts with defenses
        alert_scenarios = [
            {
                'user': 'john.doe',
                'event': 'DELETE',
                'risk': 0.85,
                'reason': 'Excessive delete operations detected',
                'rule': 'Excessive Deletes',
                'defense': 'User is performing end-of-month cleanup as part of document retention policy. This is a scheduled activity.',
                'confidence': 0.80,
                'evidence': ['Monthly cleanup schedule', 'User has admin role', 'All deletes in Archive folder'],
                'mitigation': 'Verify deleted items were within scope. Enable audit logging.',
                'status': 'dismissed'
            },
            {
                'user': 'jane.smith',
                'event': 'READ',
                'risk': 0.65,
                'reason': 'Access during unusual hours (2:00 AM)',
                'rule': 'After Hours Access',
                'defense': 'User is working from different timezone (GMT+8) handling urgent client deliverable.',
                'confidence': 0.70,
                'evidence': ['Recent international travel', 'Scheduled client deadline', 'Continuous work pattern'],
                'mitigation': 'Confirm with manager. Review accessed documents.',
                'status': 'dismissed'
            },
            {
                'user': 'bob.johnson',
                'event': 'WRITE',
                'risk': 0.75,
                'reason': 'Moderate anomaly: Event deviates from user baseline',
                'rule': None,
                'defense': 'User recently promoted to senior role requiring access to different document types.',
                'confidence': 0.65,
                'evidence': ['Role change 2 weeks ago', 'Manager approved access', 'Related to new projects'],
                'mitigation': 'Update user baseline. Monitor for 30 days.',
                'status': 'dismissed'
            },
            {
                'user': 'alice.williams',
                'event': 'ADMIN_ACCESS',
                'risk': 0.95,
                'reason': 'Unauthorized admin access attempt',
                'rule': 'Admin Access',
                'defense': 'Cannot find sufficient benign justification. User role does not require admin privileges.',
                'confidence': 0.20,
                'evidence': ['No maintenance window', 'Role does not require admin', 'No change request'],
                'mitigation': 'Immediately verify with IT security. Review all admin actions.',
                'status': 'escalated'
            },
            {
                'user': 'charlie.brown',
                'event': 'DELETE',
                'risk': 0.70,
                'reason': 'Multiple delete operations on sensitive documents',
                'rule': 'Excessive Deletes',
                'defense': 'User completing project closeout. Deleting draft versions after final approval.',
                'confidence': 0.75,
                'evidence': ['Project completion confirmed', 'Only draft versions deleted', 'Final versions retained'],
                'mitigation': 'Verify project closeout documentation.',
                'status': 'dismissed'
            },
        ]
        
        for scenario in alert_scenarios:
            timestamp = datetime.utcnow() - timedelta(hours=random.randint(1, 12))
            
            # Create audit log
            audit_log = audit_repo.create(
                user_id=scenario['user'],
                action=scenario['event'],
                metadata={
                    'record_type': 'Document',
                    'record_title': 'Sensitive_Document.pdf'
                }
            )
            
            # Create alert result
            alert_repo.create(
                audit_log_id=audit_log.id,
                user_id=scenario['user'],
                event_type=scenario['event'],
                timestamp=timestamp,
                is_alert=True,
                risk_score=scenario['risk'],
                alert_reason=scenario['reason'],
                rule_triggered=scenario.get('rule'),
                distance_score=random.uniform(0.5, 2.0) if not scenario.get('rule') else None,
                defense_generated=True,
                defense_justification=scenario['defense'],
                defense_confidence=scenario['confidence'],
                supporting_evidence=scenario['evidence'],
                risk_mitigation=scenario['mitigation'],
                final_status=scenario['status'],
                dismissed=(scenario['status'] == 'dismissed')
            )
        
        logger.info("Generated 5 sample alerts")
        
        # Generate a few more recent alerts
        for i in range(5):
            user = random.choice(users)
            event = random.choice(['DELETE', 'ADMIN_ACCESS', 'WRITE'])
            timestamp = datetime.utcnow() - timedelta(minutes=random.randint(1, 60))
            
            audit_log = audit_repo.create(
                user_id=user,
                action=event,
                metadata={'record_type': 'Document'}
            )
            
            alert_repo.create(
                audit_log_id=audit_log.id,
                user_id=user,
                event_type=event,
                timestamp=timestamp,
                is_alert=True,
                risk_score=random.uniform(0.6, 0.9),
                alert_reason=f"Suspicious {event} activity detected",
                defense_generated=True,
                defense_justification="Possible legitimate business activity based on user role.",
                defense_confidence=random.uniform(0.4, 0.8),
                final_status='pending',
                dismissed=False
            )
        
        logger.info("Generated 5 recent pending alerts")
        
        logger.info("✅ Sample data generation completed!")
        logger.info("\nYou can now run: streamlit run src/interface/app.py")
        
    except Exception as e:
        logger.error(f"Error generating sample data: {e}", exc_info=True)
    finally:
        session.close()
        db.close()


if __name__ == "__main__":
    generate_sample_data()
