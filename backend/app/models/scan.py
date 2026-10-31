import uuid
import enum
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Integer, Float, Enum, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from app.database.session import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    application_id = Column(String, ForeignKey("applications.id"), nullable=True)

    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)

    max_depth = Column(Integer, default=2)
    max_urls = Column(Integer, default=50)
    request_delay = Column(Float, default=0.25)
    modules = Column(JSON, default=list)  # list of enabled module names
    enable_browser_discovery = Column(Boolean, default=True)
    route_summary = Column(JSON, default=dict)
    coverage_summary = Column(JSON, default=dict)

    current_module = Column(String, nullable=True)
    urls_discovered = Column(Integer, default=0)
    urls_scanned = Column(Integer, default=0)
    parameters_found = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    progress_percent = Column(Float, default=0.0)

    error_message = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="scans")
    application = relationship("Application", back_populates="scans")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    summary = relationship("ScanSummary", back_populates="scan", uselist=False, cascade="all, delete-orphan")
