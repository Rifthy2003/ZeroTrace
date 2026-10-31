"""
In-memory data structures passed between scanner modules during a scan.
These are converted to Finding ORM rows by the engine once a scan completes
(or incrementally, module by module).
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any


@dataclass
class DiscoveredParameter:
    name: str
    location: str  # "query" | "form" | "json"
    sample_value: Optional[str] = None


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    redirected_to: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    html: str = ""  # full (capped) HTML, transient, never persisted
    parameters: List[DiscoveredParameter] = field(default_factory=list)
    has_form: bool = False


@dataclass
class ScanFinding:
    type: str
    category: str
    url: str
    method: str
    severity: str
    confidence: str
    evidence: str
    description: str
    impact: str
    remediation: str
    parameter: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    mitre_attack: Optional[str] = None
    detection_status: Optional[str] = None
    raw_instances: int = 1
    evidence_details: Dict[str, Any] = field(default_factory=dict)
