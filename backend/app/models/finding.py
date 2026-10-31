import uuid
import enum
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, Text, Integer, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base


class Severity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, enum.Enum):
    CONFIRMED = "Confirmed"
    HIGH = "High confidence"
    MEDIUM = "Medium confidence"
    LOW = "Low confidence"
    INFORMATIONAL = "Informational"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    type = Column(String, nullable=False)          # e.g. "SQL Injection"
    category = Column(String, nullable=False)       # e.g. "Injection"
    owasp_category = Column(String, nullable=True)  # e.g. "A03:2021 - Injection"

    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    parameter = Column(String, nullable=True)

    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Enum(Confidence), nullable=False)

    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    status = Column(String, default="open", nullable=False, index=True)
    fingerprint = Column(String, index=True, nullable=True)
    status_note = Column(Text, nullable=True)
    status_updated_at = Column(DateTime, nullable=True)

    cwe_id = Column(String, nullable=True)
    mitre_attack = Column(String, nullable=True)
    detection_status = Column(String, default="Confirmed", nullable=True)
    raw_instances = Column(Integer, default=1, nullable=False)
    evidence_details = Column(JSON, default=dict, nullable=True)

    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
