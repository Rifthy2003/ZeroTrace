import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    redirected_to = Column(String, nullable=True)
    response_headers = Column(JSON, default=dict)
    has_form = Column(String, default="false")

    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="endpoints")
    parameters = relationship("Parameter", back_populates="endpoint", cascade="all, delete-orphan")
