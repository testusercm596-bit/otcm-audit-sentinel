"""
Core domain entities for the OTCM Audit Sentinel system
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from enum import Enum


class AuditStatus(Enum):
    """Audit status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(Enum):
    """Security severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuditRecord:
    """Core audit record entity"""
    id: Optional[str]
    document_id: str
    timestamp: datetime
    user_id: str
    action: str
    status: AuditStatus
    metadata: dict
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class SecurityFinding:
    """Security finding entity"""
    id: Optional[str]
    audit_record_id: str
    severity: SeverityLevel
    description: str
    recommendation: str
    detected_by: str  # 'sentinel' or 'hallucinator'
    confidence_score: float
    created_at: Optional[datetime] = None


@dataclass
class ContentDocument:
    """Content Manager document entity"""
    id: str
    name: str
    type: str
    owner_id: str
    created_at: datetime
    modified_at: datetime
    permissions: List[dict]
    metadata: dict
