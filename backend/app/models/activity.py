import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base


class Activity(Base):
    __tablename__ = "activities"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    application_id = Column(String, ForeignKey("applications.id", ondelete="SET NULL"), nullable=True)

    event_type = Column(String, nullable=False, index=True)  # scan_started, scan_completed, scan_failed, vulns_detected, vuln_resolved, report_generated, status_updated
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="info")  # info, warning, critical, success
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    activity_metadata = Column("metadata", JSON, default=dict)

    scan = relationship("Scan", backref="activities")
    application = relationship("Application", back_populates="activities")

