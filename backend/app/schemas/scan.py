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
    modules: Optional[List[str]] = None
    authorization_confirmed: bool = False
    enable_browser_discovery: bool = True
    auth_config: Optional[dict] = None
    scan_type: Optional[str] = "Quick Scan"
    profile_id: Optional[str] = None
    program_id: Optional[str] = None

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


class ScanRenameRequest(BaseModel):
    name: str


class ScanBulkActionRequest(BaseModel):
    scan_ids: List[str]


class ScanResponse(BaseModel):
    id: str
    target_id: str
    name: Optional[str] = None
    application_id: Optional[str] = None
    application_name: Optional[str] = None
    target_url: Optional[str] = None
    hostname: Optional[str] = None
    status: str
    is_deleted: Optional[bool] = False
    deleted_at: Optional[datetime] = None
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
    unique_findings_count: Optional[int] = 0
    raw_occurrences_count: Optional[int] = 0
    security_rating: Optional[str] = None
    security_score: Optional[float] = None
    progress_percent: float
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    scan_type: Optional[str] = "Quick Scan"
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    program_id: Optional[str] = None
    program_name: Optional[str] = None
    effective_restrictions: Optional[dict] = None

    class Config:
        from_attributes = True


class FindingStatusHistoryResponse(BaseModel):
    id: str
    finding_id: str
    old_status: Optional[str] = None
    new_status: str
    note: Optional[str] = None
    user: str = "Security Researcher"
    timestamp: datetime

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
    finding_group: Optional[str] = "other_vulnerabilities"
    raw_instances: Optional[int] = 1
    evidence_details: Optional[dict] = None
    status_history: Optional[List[FindingStatusHistoryResponse]] = None
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
    scan_type: Optional[str] = "Quick Scan"
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    program_id: Optional[str] = None
    program_name: Optional[str] = None
    effective_restrictions: Optional[dict] = None
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
    last_scanned_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HistoryPointResponse(BaseModel):
    scan_id: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    scan_type: Optional[str] = "Quick Scan"
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    program_id: Optional[str] = None
    program_name: Optional[str] = None
    effective_restrictions: Optional[dict] = None
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
    status: str
    note: Optional[str] = None
    user: Optional[str] = "Security Researcher"


class ScanProfileCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    modules: List[str]
    max_depth: Optional[int] = 2
    max_urls: Optional[int] = 50
    max_parameters: Optional[int] = 50
    request_rate: Optional[float] = 5.0
    concurrency: Optional[int] = 2
    request_timeout: Optional[float] = 10.0
    allowed_http_methods: Optional[List[str]] = ["GET", "POST"]
    enable_browser_discovery: Optional[bool] = True
    send_payloads: Optional[bool] = True
    auth_config: Optional[dict] = None


class ScanProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    modules: Optional[List[str]] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    max_parameters: Optional[int] = None
    request_rate: Optional[float] = None
    concurrency: Optional[int] = None
    request_timeout: Optional[float] = None
    allowed_http_methods: Optional[List[str]] = None
    enable_browser_discovery: Optional[bool] = None
    send_payloads: Optional[bool] = None
    auth_config: Optional[dict] = None


class ScanProfileResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    is_builtin: bool = False
    is_default: bool = False
    modules: List[str]
    max_depth: int
    max_urls: int
    max_parameters: int
    request_rate: float
    concurrency: int
    request_timeout: float
    allowed_http_methods: List[str]
    enable_browser_discovery: bool
    send_payloads: bool
    auth_config: Optional[dict] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanProgramCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    target_domains: List[str]
    url_patterns: Optional[List[str]] = []
    out_of_scope_paths: Optional[List[str]] = []
    allowed_modules: Optional[List[str]] = []
    prohibited_modules: Optional[List[str]] = []
    max_requests_per_second: Optional[float] = None
    max_concurrency: Optional[int] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    allow_automated_scanning: Optional[bool] = True
    auth_config: Optional[dict] = None
    notes: Optional[str] = None


class ScanProgramUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_domains: Optional[List[str]] = None
    url_patterns: Optional[List[str]] = None
    out_of_scope_paths: Optional[List[str]] = None
    allowed_modules: Optional[List[str]] = None
    prohibited_modules: Optional[List[str]] = None
    max_requests_per_second: Optional[float] = None
    max_concurrency: Optional[int] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    allow_automated_scanning: Optional[bool] = None
    auth_config: Optional[dict] = None
    notes: Optional[str] = None


class ScanProgramResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    target_domains: List[str]
    url_patterns: List[str]
    out_of_scope_paths: List[str]
    allowed_modules: List[str]
    prohibited_modules: List[str]
    max_requests_per_second: Optional[float] = None
    max_concurrency: Optional[int] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    allow_automated_scanning: bool
    auth_config: Optional[dict] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComparedFindingItem(BaseModel):
    fingerprint: str
    type: str
    category: str
    url: str
    method: str
    parameter: Optional[str] = None
    severity: str
    status: str
    comparison_status: str  # "new", "fixed", "recurring", "unchanged"
    base_finding_id: Optional[str] = None
    target_finding_id: Optional[str] = None
    affected_urls: List[str] = []
    raw_instances: int = 1
    evidence_snippet: Optional[str] = None


class ScanComparisonResponse(BaseModel):
    base_scan: ScanResponse
    target_scan: ScanResponse
    target_domain: str
    base_score: float
    target_score: float
    score_delta: float
    base_unique_count: int
    target_unique_count: int
    count_delta: int
    severity_changes: dict
    coverage_changes: dict
    findings_summary: dict
    compared_findings: List[ComparedFindingItem]


class EndpointCoverageItem(BaseModel):
    id: str
    url: str
    method: str
    endpoint_type: str
    source: str
    status_code: Optional[int] = None
    parameters: List[dict] = []
    testing_status: str
    is_tested: bool
    modules_executed: List[str] = []
    findings_count: int = 0
    findings: List[dict] = []


class EndpointCoverageResponse(BaseModel):
    scan_id: str
    target_url: str
    hostname: str
    scan_status: str
    created_at: datetime
    discovered_pages: int
    discovered_endpoints: int
    discovered_forms: int
    discovered_parameters: int
    tested_endpoints: int
    untested_endpoints: int
    tested_parameters: int
    untested_parameters: int
    successful_requests: int
    failed_requests: int
    skipped_endpoints: int
    auth_protected_endpoints: int
    coverage_percentage: float
    method_distribution: dict
    module_matrix: List[dict]
    endpoints: List[EndpointCoverageItem]


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


