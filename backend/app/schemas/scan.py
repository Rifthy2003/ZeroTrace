from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, field_validator


AVAILABLE_MODULES = [
    "sql_injection",
    "xss",
    "csrf",
    "security_headers",
    "directory_listing",
    "sensitive_files",
    "open_redirect",
    "information_disclosure",
    "cookie_security",
]


class ScanCreateRequest(BaseModel):
    target_url: str
    max_depth: int = 2
    max_urls: int = 50
    request_delay: float = 0.25
    modules: List[str] = AVAILABLE_MODULES
    authorization_confirmed: bool = False

    @field_validator("authorization_confirmed")
    @classmethod
    def must_confirm_authorization(cls, v):
        if not v:
            raise ValueError(
                "You must confirm you are authorized to test this target "
                "(authorization_confirmed=true)."
            )
        return v

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v):
        invalid = set(v) - set(AVAILABLE_MODULES)
        if invalid:
            raise ValueError(f"Unknown modules: {invalid}")
        return v


class ScanResponse(BaseModel):
    id: str
    target_id: str
    status: str
    max_depth: int
    max_urls: int
    request_delay: float
    modules: List[str]
    current_module: Optional[str] = None
    urls_discovered: int
    urls_scanned: int
    parameters_found: int
    findings_count: int
    progress_percent: float
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    type: str
    category: str
    owasp_category: Optional[str]
    url: str
    method: str
    parameter: Optional[str]
    severity: str
    confidence: str
    evidence: Optional[str]
    description: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


class ScanSummaryResponse(BaseModel):
    total_urls: int
    total_endpoints: int
    total_parameters: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int

    class Config:
        from_attributes = True
