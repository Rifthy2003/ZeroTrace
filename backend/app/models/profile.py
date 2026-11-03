import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Integer, Float, Boolean, Text, JSON
from app.database.session import Base


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    is_builtin = Column(Boolean, default=False, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)

    modules = Column(JSON, default=list)  # list of enabled module names
    max_depth = Column(Integer, default=2, nullable=False)
    max_urls = Column(Integer, default=50, nullable=False)
    max_parameters = Column(Integer, default=50, nullable=False)
    request_rate = Column(Float, default=5.0, nullable=False)  # requests per second
    concurrency = Column(Integer, default=2, nullable=False)
    request_timeout = Column(Float, default=10.0, nullable=False)  # seconds
    allowed_http_methods = Column(JSON, default=lambda: ["GET", "POST"])
    enable_browser_discovery = Column(Boolean, default=True, nullable=False)
    send_payloads = Column(Boolean, default=True, nullable=False)  # False for passive scan
    auth_config = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ScanProgram(Base):
    __tablename__ = "scan_programs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)

    target_domains = Column(JSON, default=list)        # e.g. ["example.com", "*.example.com", "localhost"]
    url_patterns = Column(JSON, default=list)          # regex or wildcard patterns allowed
    out_of_scope_paths = Column(JSON, default=list)    # paths strictly out-of-scope (e.g. /logout, /billing)
    allowed_modules = Column(JSON, default=list)       # if non-empty, only these modules permitted
    prohibited_modules = Column(JSON, default=list)    # modules explicitly prohibited by program
    max_requests_per_second = Column(Float, nullable=True)
    max_concurrency = Column(Integer, nullable=True)
    max_depth = Column(Integer, nullable=True)
    max_urls = Column(Integer, nullable=True)
    allow_automated_scanning = Column(Boolean, default=True, nullable=False)
    auth_config = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

