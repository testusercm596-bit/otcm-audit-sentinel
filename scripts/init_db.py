"""
Database initialization script
"""
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.infrastructure.database import db
from src.config.settings import settings
from src.domain.alert_models import AlertResult  # Ensure table is created

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Initialize the database"""
    logger.info("Starting database initialization...")
    
    # Validate settings
    if not settings.validate():
        logger.error("Invalid configuration. Please check your .env file")
        return False
    
    try:
        # Connect to database
        logger.info(f"Connecting to database...")
        db.connect()
        
        # Initialize database (enable pgvector and create tables)
        logger.info("Enabling pgvector extension and creating tables...")
        db.init_db()
        
        logger.info("✅ Database initialization completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        return False
    
    finally:
        db.close()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
