import uuid

from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base


class Parameter(Base):
    __tablename__ = "parameters"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_id = Column(String, ForeignKey("endpoints.id"), nullable=False)

    name = Column(String, nullable=False)
    location = Column(String, default="query")  # query | form | json
    sample_value = Column(String, nullable=True)

    endpoint = relationship("Endpoint", back_populates="parameters")
