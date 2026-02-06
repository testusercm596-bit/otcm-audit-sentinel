"""
Database initialization script for OTCM Audit Sentinel
"""
import sys
import os
import logging
from sqlalchemy import text

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure.database import db
from config.settings import settings
from src.domain.alert_models import AlertResult  # Ensure table is created

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_vector_indexes():
    """Create vector similarity search indexes"""
    logger.info("Creating vector similarity search indexes...")
    
    try:
        with db.engine.connect() as conn:
            # Create IVFFlat index for cosine similarity search
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS audit_logs_embedding_idx 
                ON audit_logs USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100)
            """))
            
            # Create additional useful indexes
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS audit_logs_user_timestamp_idx 
                ON audit_logs (user_name, timestamp)
            """))
            
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS audit_logs_event_type_idx 
                ON audit_logs (event_type, object_type)
            """))
            
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS audit_logs_security_violation_idx 
                ON audit_logs (is_security_violation) WHERE is_security_violation = true
            """))
            
            conn.commit()
            logger.info("✅ Vector and utility indexes created successfully")
            
    except Exception as e:
        logger.error(f"❌ Failed to create indexes: {e}")
        raise


def main():
    """Initialize the database"""
    logger.info("=" * 60)
    logger.info("OTCM Audit Sentinel - Database Initialization")
    logger.info("=" * 60)
    
    # Validate settings
    if not settings.validate():
        logger.error("❌ Invalid configuration. Please check your .env file")
        return False
    
    try:
        # Connect to database
        logger.info(f"\n📊 Connecting to database...")
        db.connect()
        logger.info("✅ Database connection established")
        
        # Drop existing tables to recreate with correct schema
        logger.info("\n🗑️  Dropping existing tables (if any)...")
        with db.engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS audit_logs CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS security_findings CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS alert_results CASCADE"))
            conn.commit()
            logger.info("✅ Existing tables dropped")
        
        # Initialize database (enable pgvector and create tables)
        logger.info("\n🔧 Enabling pgvector extension...")
        db.init_db()
        logger.info("✅ Database tables created")
        
        # Create vector indexes
        logger.info("\n🔍 Creating vector similarity search indexes...")
        create_vector_indexes()
        
        # Verify setup
        logger.info("\n✅ Verifying database setup...")
        with db.engine.connect() as conn:
            # Check pgvector extension
            result = conn.execute(text("SELECT extname FROM pg_extension WHERE extname = 'vector'"))
            if result.fetchone():
                logger.info("  ✓ pgvector extension: Enabled")
            
            # Check audit_logs table
            result = conn.execute(text("""
                SELECT COUNT(*) FROM information_schema.tables 
                WHERE table_name = 'audit_logs'
            """))
            if result.fetchone()[0] > 0:
                logger.info("  ✓ audit_logs table: Created")
                
                # Check for vector column
                result = conn.execute(text("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = 'audit_logs' AND column_name = 'embedding'
                """))
                if result.fetchone():
                    logger.info("  ✓ embedding column: Ready for vectors")
            
            # Check indexes
            result = conn.execute(text("""
                SELECT indexname FROM pg_indexes 
                WHERE tablename = 'audit_logs' AND indexname LIKE '%embedding%'
            """))
            if result.fetchone():
                logger.info("  ✓ Vector similarity index: Created")
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ Database initialization completed successfully!")
        logger.info("=" * 60)
        logger.info("\n📝 Next steps:")
        logger.info("  1. Run: python scripts/train_hallucinator_with_data.py")
        logger.info("  2. This will populate the database with training data")
        logger.info("  3. Then you can query for similar events using embeddings\n")
        
        return True
        
    except Exception as e:
        logger.error(f"\n❌ Database initialization failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
    finally:
        db.close()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
