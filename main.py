"""
Main entry point for OTCM Audit Sentinel
Orchestrates the continuous monitoring and analysis pipeline
"""
import sys
import os
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from config.settings import settings
from src.infrastructure.database import db
from src.infrastructure.cm_client import ContentManagerClient
from src.infrastructure.repositories import AuditLogRepository
from src.infrastructure.alert_repository import AlertResultRepository
from src.application.sentinel import SentinelAgent, UserProfile
from src.application.hallucinator import HallucinatorAgent

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.ai.model if hasattr(settings, 'ai') else 'INFO', logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuditSentinelOrchestrator:
    """
    Main orchestrator for the OTCM Audit Sentinel system
    
    Coordinates:
    1. Fetching logs from Content Manager
    2. Storing logs in database
    3. Running Sentinel detection
    4. Running Hallucinator defense
    5. Making final decisions and storing results
    """
    
    def __init__(self):
        """Initialize the orchestrator and all components"""
        logger.info("Initializing OTCM Audit Sentinel...")
        
        # Validate configuration
        if not settings.validate():
            raise RuntimeError("Invalid configuration. Check your .env file")
        
        # Initialize database
        logger.info("Connecting to database...")
        db.connect()
        db.init_db()
        
        # Initialize Content Manager client
        logger.info("Setting up Content Manager client...")
        self.cm_client = ContentManagerClient(
            base_url=settings.content_manager.base_url,
            username=settings.content_manager.username,
            password=settings.content_manager.password,
            domain=settings.content_manager.domain
        )
        
        # Initialize security rules
        self.security_rules = self._load_security_rules()
        
        # Initialize user profiles (could be loaded from DB in production)
        self.user_profiles = {}
        
        # Initialize Sentinel Agent
        logger.info("Initializing Sentinel Agent...")
        self.sentinel = SentinelAgent(
            rules=self.security_rules,
            user_profiles=self.user_profiles
        )
        
        # Initialize Hallucinator Agent
        logger.info("Initializing Hallucinator Agent...")
        self.hallucinator = HallucinatorAgent(
            model=settings.hallucinator_ai.model,
            temperature=settings.hallucinator_ai.temperature,
            api_key=settings.hallucinator_ai.api_key,
            api_base=settings.hallucinator_ai.api_base
        )
        
        # Track last check time
        self.last_check_time = datetime.utcnow() - timedelta(hours=1)
        
        # Statistics
        self.stats = {
            'logs_processed': 0,
            'alerts_generated': 0,
            'alerts_dismissed': 0,
            'alerts_escalated': 0
        }
        
        logger.info("✅ OTCM Audit Sentinel initialized successfully")
    
    def _load_security_rules(self) -> List[Dict]:
        """Load security rules from configuration"""
        # In production, these could be loaded from database or config file
        return [
            {
                'name': 'Excessive Deletes',
                'condition': 'event_type',
                'operator': '==',
                'value': 'DELETE',
                'threshold': 5,
                'risk_score': 0.8,
                'description': 'User performed more than 5 delete operations'
            },
            {
                'name': 'Sensitive Document Access',
                'condition': 'record_type',
                'operator': '==',
                'value': 'Contract',
                'threshold': None,
                'risk_score': 0.7,
                'description': 'Access to sensitive contract documents'
            },
            {
                'name': 'After Hours Access',
                'condition': 'hour',
                'operator': 'in',
                'value': [0, 1, 2, 3, 4, 5, 22, 23],
                'risk_score': 0.6,
                'description': 'Access during unusual hours'
            }
        ]
    
    def run_once(self):
        """Run a single iteration of the monitoring loop"""
        logger.info(f"Fetching logs since {self.last_check_time}")
        
        # Get database session
        session = db.get_session()
        audit_repo = AuditLogRepository(session)
        alert_repo = AlertResultRepository(session)
        
        try:
            # Step 1: Fetch recent logs from Content Manager
            logs = self.cm_client.fetch_and_embed_logs(self.last_check_time)
            logger.info(f"Fetched {len(logs)} new audit logs")
            
            # Step 2: Process each log
            for log in logs:
                self._process_log(log, audit_repo, alert_repo)
                self.stats['logs_processed'] += 1
            
            # Update last check time
            self.last_check_time = datetime.utcnow()
            
            # Log statistics
            logger.info(f"Statistics: {self.stats}")
            
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}", exc_info=True)
        finally:
            session.close()
    
    def _process_log(self, log: Dict, audit_repo: AuditLogRepository, alert_repo: AlertResultRepository):
        """Process a single audit log"""
        user_id = log.get('actor', 'unknown')
        event_type = log.get('event', 'UNKNOWN')
        
        # Step 1: Store log in database
        audit_log = audit_repo.create(
            user_id=user_id,
            action=event_type,
            event_metadata=log,
            embedding=log.get('embedding')
        )
        
        # Step 2: Prepare event for Sentinel
        event = {
            'user_id': user_id,
            'event_type': event_type,
            'timestamp': log.get('timestamp'),
            'record_type': log.get('record_type'),
            'record_title': log.get('record_title'),
            'embedding': log.get('embedding'),
            'metadata': log
        }
        
        # Step 3: Run Sentinel detection
        alert = self.sentinel.evaluate_event(event)
        
        if alert.is_alert:
            logger.warning(f"🚨 Alert for user {user_id}: {alert.reason}")
            self.stats['alerts_generated'] += 1
            
            # Step 4: Fetch user history from database
            user_history = self._get_user_history(user_id, audit_repo)
            
            # Step 5: Run Hallucinator defense
            defense = self.hallucinator.generate_defense(
                {
                    'is_alert': True,
                    'risk_score': alert.risk_score,
                    'reason': alert.reason,
                    'event': event
                },
                user_history
            )
            
            logger.info(f"🛡️  Defense generated with confidence: {defense.confidence:.2f}")
            
            # Step 6: Make final decision
            if self.hallucinator.should_dismiss_alert(defense, confidence_threshold=0.7):
                final_status = 'dismissed'
                dismissed = True
                self.stats['alerts_dismissed'] += 1
                logger.info(f"✅ Alert dismissed: {defense.justification[:100]}...")
            else:
                final_status = 'escalated'
                dismissed = False
                self.stats['alerts_escalated'] += 1
                logger.warning(f"⚠️  Alert escalated for investigation")
            
            # Step 7: Store result in database
            alert_result = alert_repo.create(
                audit_log_id=audit_log.id,
                user_id=user_id,
                event_type=event_type,
                timestamp=datetime.fromisoformat(log.get('timestamp')) if log.get('timestamp') else datetime.utcnow(),
                is_alert=True,
                risk_score=alert.risk_score,
                alert_reason=alert.reason,
                rule_triggered=alert.rule_triggered,
                distance_score=alert.distance_score,
                defense_generated=True,
                defense_justification=defense.justification,
                defense_confidence=defense.confidence,
                supporting_evidence=defense.supporting_evidence,
                risk_mitigation=defense.risk_mitigation,
                final_status=final_status,
                dismissed=dismissed,
                event_metadata=log
            )
            
            logger.info(f"💾 Alert result saved: ID={alert_result.id}, Status={final_status}")
        
        else:
            # No alert - just log it
            logger.debug(f"✓ Event normal for user {user_id}")
    
    def _get_user_history(self, user_id: str, audit_repo: AuditLogRepository) -> List[Dict]:
        """Get user's historical events from database"""
        audit_logs = audit_repo.get_by_user(user_id, limit=50)
        
        history = []
        for log in audit_logs:
            if log.event_metadata:
                history.append(log.event_metadata)
            else:
                history.append({
                    'event_type': log.action,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'user_id': log.user_id
                })
        
        return history
    
    def run_continuous(self, interval_seconds: int = 60):
        """
        Run continuous monitoring loop
        
        Args:
            interval_seconds: Seconds between checks (default: 60)
        """
        logger.info(f"Starting continuous monitoring (check interval: {interval_seconds}s)")
        logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                self.run_once()
                logger.info(f"Sleeping for {interval_seconds} seconds...")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            logger.info("Stopping OTCM Audit Sentinel...")
            self._shutdown()
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            self._shutdown()
    
    def _shutdown(self):
        """Cleanup and shutdown"""
        logger.info("Final statistics:")
        for key, value in self.stats.items():
            logger.info(f"  {key}: {value}")
        
        db.close()
        logger.info("✅ Shutdown complete")


def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        🛡️  OTCM AUDIT SENTINEL                           ║
║                                                           ║
║        AI-Powered Security Analysis Tool                 ║
║        for OpenText Content Manager                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Create orchestrator
        orchestrator = AuditSentinelOrchestrator()
        
        # Run continuous monitoring
        orchestrator.run_continuous(interval_seconds=60)
        
    except Exception as e:
        logger.error(f"Failed to start: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
