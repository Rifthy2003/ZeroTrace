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
    "command_injection",
    "ssti",
    "cors",
    "clickjacking",
    "path_traversal",
    "auth_security",
    "access_control",
    "graphql",
]


class ScanCreateRequest(BaseModel):
    target_url: str
    application_name: Optional[str] = None
    application_id: Optional[str] = None
    max_depth: int = 2
    max_urls: int = 50
    request_delay: float = 0.25
    modules: List[str] = AVAILABLE_MODULES
    authorization_confirmed: bool = False
    enable_browser_discovery: bool = True
    auth_config: Optional[dict] = None

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
    application_id: Optional[str] = None
    application_name: Optional[str] = None
    target_url: Optional[str] = None
    hostname: Optional[str] = None
    status: str
    max_depth: int
    max_urls: int
    request_delay: float
    modules: List[str]
    enable_browser_discovery: Optional[bool] = True
    route_summary: Optional[dict] = None
    coverage_summary: Optional[dict] = None
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
    duration_seconds: Optional[float] = None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    type: str
    category: str
    owasp_category: Optional[str] = None
    url: str
    method: str
    parameter: Optional[str] = None
    severity: str
    confidence: str
    evidence: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    status: str = "open"
    fingerprint: Optional[str] = None
    status_note: Optional[str] = None
    status_updated_at: Optional[datetime] = None
    cwe_id: Optional[str] = None
    mitre_attack: Optional[str] = None
    detection_status: Optional[str] = "Confirmed"
    raw_instances: Optional[int] = 1
    evidence_details: Optional[dict] = None
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


class ScoreDeductionResponse(BaseModel):
    finding_type: str
    severity: str
    confidence: str
    points_deducted: float
    occurrences: int
    summary: str


class SeverityCountResponse(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    total: int


class CoverageResponse(BaseModel):
    urls_scanned: int
    urls_discovered: int
    parameters_found: int
    max_depth: int
    max_urls: int
    modules: List[str]
    duration_seconds: Optional[float] = None
    routes_discovered: List[str] = []
    routes_visited: List[str] = []
    routes_tested: List[str] = []
    routes_failed: List[str] = []
    routes_auth_required: List[str] = []
    limitations: List[str] = []
    coverage_summary: Optional[dict] = None


class RemediationResponse(BaseModel):
    severity: str
    finding_type: str
    remediation: str


class SecurityPostureResponse(BaseModel):
    scan_id: str
    target_url: str
    hostname: str
    score: float
    rating: str
    rating_label: str
    rating_color: str
    is_preliminary: bool
    preliminary_reasons: List[str]
    total_penalty: float
    scan_status: str
    raw_counts: SeverityCountResponse
    unique_counts: SeverityCountResponse
    confirmed_count: int
    manual_verification_count: int
    unique_confirmed_count: int
    unique_manual_verification_count: int
    coverage: CoverageResponse
    score_deductions: List[ScoreDeductionResponse]
    main_reasons: List[str]
    recommendations: List[RemediationResponse]
    disclaimer: str


class ApplicationCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    target_url: Optional[str] = None


class ApplicationUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ApplicationResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    target_url: Optional[str] = None
    hostname: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    total_scans: int = 0
    latest_scan_id: Optional[str] = None
    latest_scan_date: Optional[datetime] = None
    latest_scan_status: Optional[str] = None
    latest_scan_duration: Optional[float] = None
    latest_score: Optional[float] = None
    latest_rating: Optional[str] = None
    latest_rating_color: Optional[str] = None
    is_preliminary: bool = False
    finding_counts: dict = {}
    discovered_routes_count: int = 0
    tested_routes_count: int = 0
    auth_routes_count: int = 0
    failed_routes_count: int = 0
    coverage_percentage: float = 0.0

    class Config:
        from_attributes = True


class HistoryPointResponse(BaseModel):
    scan_id: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    status: str
    score: float
    rating: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    routes_discovered: int = 0
    routes_tested: int = 0


class ApplicationTrendResponse(BaseModel):
    application_id: str
    application_name: str
    target_url: Optional[str] = None
    hostname: Optional[str] = None
    latest_score: Optional[float] = None
    previous_score: Optional[float] = None
    score_delta: Optional[float] = None
    new_vulnerabilities_count: int = 0
    resolved_vulnerabilities_count: int = 0
    persistent_vulnerabilities_count: int = 0
    reopened_vulnerabilities_count: int = 0
    new_vulnerabilities: List[dict] = []
    resolved_vulnerabilities: List[dict] = []
    persistent_vulnerabilities: List[dict] = []
    reopened_vulnerabilities: List[dict] = []
    history: List[HistoryPointResponse] = []


class FindingStatusUpdateRequest(BaseModel):
    status: str  # "open", "fixed", "accepted_risk", "reopened"
    note: Optional[str] = None


class ActivityResponse(BaseModel):
    id: str
    event_type: str
    title: str
    description: Optional[str] = None
    severity: str
    timestamp: datetime
    scan_id: Optional[str] = None
    application_id: Optional[str] = None
    metadata: dict = {}

    class Config:
        from_attributes = True


class ExecutiveOverviewResponse(BaseModel):
    total_monitored_websites: int
    total_scans: int
    average_security_score: float
    websites_with_high_risk: int
    open_high_critical_count: int
    recently_completed_scans: int
    by_severity: dict
    by_type: dict
    coverage_overview: dict


