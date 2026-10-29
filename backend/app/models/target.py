import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.orm import relationship
from app.database.session import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    base_url = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=False, index=True)
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
