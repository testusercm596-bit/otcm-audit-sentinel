"""
Database connection and repository implementations
"""
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Float, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.domain.models import Base, AuditLog
from src.domain.alert_models import AlertResult
from config.settings import settings

logger = logging.getLogger(__name__)


class SecurityFindingModel(Base):
    """SQLAlchemy model for security findings"""
    __tablename__ = 'security_findings'
    
    id = Column(String, primary_key=True)
    audit_record_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String, nullable=False)
    recommendation = Column(String, nullable=False)
    detected_by = Column(String, nullable=False)
    confidence_score = Column(Float, nullable=False)
    created_at = Column(DateTime)


class DatabaseConnection:
    """PostgreSQL database connection manager with pgvector support"""
    
    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = connection_string or settings.database.url
        self.engine = None
        self.SessionLocal = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.engine = create_engine(
                self.connection_string,
                pool_size=settings.database.pool_size,
                max_overflow=settings.database.max_overflow,
                echo=settings.database.echo
            )
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            logger.info("Database connection established successfully")
            return self.engine
        except SQLAlchemyError as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def init_db(self):
        """
        Initialize database:
        - Enable pgvector extension
        - Create all tables
        """
        if self.engine is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        
        try:
            # Enable pgvector extension
            with self.engine.connect() as conn:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                conn.commit()
                logger.info("pgvector extension enabled")
            
            # Create all tables
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def create_tables(self):
        """Create all tables (deprecated - use init_db instead)"""
        if self.engine is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self) -> Session:
        """Get a database session"""
        if self.SessionLocal is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.SessionLocal()
    
    def close(self):
        """Close database connection"""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connection closed")


# Global database instance
db = DatabaseConnection()
