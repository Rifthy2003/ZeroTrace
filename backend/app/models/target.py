import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id = Column(String, ForeignKey("applications.id"), nullable=True)
    name = Column(String, nullable=True)
    base_url = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=False, index=True)
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    application = relationship("Application", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
