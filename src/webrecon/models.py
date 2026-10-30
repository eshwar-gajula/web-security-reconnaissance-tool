from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class TargetSpec:
    original: str
    scheme: str
    hostname: str
    port: int

    @property
    def origin(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{host}{suffix}"

    @property
    def root_url(self) -> str:
        return f"{self.origin}/"


@dataclass(slots=True)
class DnsObservation:
    name: str
    record_type: str
    status: str
    values: list[str] = field(default_factory=list)
    ttl: int | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EndpointObservation:
    path: str
    method: str
    status_code: int | None
    discovered_by: list[str] = field(default_factory=list)
    probed: bool = False
    content_type: str | None = None
    content_length: int | None = None
    error_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CookieAssessment:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HttpObservation:
    url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    cookies: list[CookieAssessment] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    endpoint_count: int = 0
    response_bytes_sampled: int = 0
    body_truncated: bool = False
    redirect_same_origin: bool | None = None
    error_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "technologies": self.technologies,
            "cookies": [item.to_dict() for item in self.cookies],
            "tls": self.tls,
            "endpoint_count": self.endpoint_count,
            "response_bytes_sampled": self.response_bytes_sampled,
            "body_truncated": self.body_truncated,
            "redirect_same_origin": self.redirect_same_origin,
            "error_type": self.error_type,
        }


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    evidence: str
    recommendation: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TargetResult:
    target: str
    origin: str
    hostname: str
    dns: list[DnsObservation] = field(default_factory=list)
    http: HttpObservation | None = None
    endpoints: list[EndpointObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "origin": self.origin,
            "hostname": self.hostname,
            "dns": [item.to_dict() for item in self.dns],
            "http": self.http.to_dict() if self.http else None,
            "endpoints": [item.to_dict() for item in self.endpoints],
            "findings": [item.to_dict() for item in self.findings],
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class ScanReport:
    scan_id: str
    started_at: str
    finished_at: str
    duration_seconds: float
    targets: list[TargetResult]
    authorization_acknowledged: bool = True
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": "web-security-reconnaissance-tool", "version": "1.0.0"},
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "authorization_acknowledged": self.authorization_acknowledged,
            "summary": {
                "targets": len(self.targets),
                "http_responses": sum(
                    target.http is not None and target.http.status_code is not None for target in self.targets
                ),
                "endpoints": sum(len(target.endpoints) for target in self.targets),
                "findings": sum(len(target.findings) for target in self.targets),
            },
            "results": [target.to_dict() for target in self.targets],
        }
