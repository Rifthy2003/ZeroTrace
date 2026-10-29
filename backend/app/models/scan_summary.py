from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base


class ScanSummary(Base):
    __tablename__ = "scan_summaries"

    scan_id = Column(String, ForeignKey("scans.id"), primary_key=True)

    total_urls = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    total_parameters = Column(Integer, default=0)

    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    informational_count = Column(Integer, default=0)

    scan = relationship("Scan", back_populates="summary")
