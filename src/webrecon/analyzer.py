from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ssl import cert_time_to_seconds

from .models import DnsObservation, Finding, TargetResult


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    evidence: str,
    recommendation: str,
    source: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        recommendation=recommendation,
        source=source,
    )


def _dns_findings(records: list[DnsObservation]) -> list[Finding]:
    findings: list[Finding] = []
    by_type = {(item.name, item.record_type): item for item in records}
    base_names = {item.name for item in records if item.record_type in {"A", "AAAA"}}
    if not base_names:
        return findings
    base = sorted(base_names)[0]

    txt = next((item.values for item in records if item.name == base and item.record_type == "TXT"), [])
    if not any("v=spf1" in value.lower() for value in txt):
        findings.append(
            _finding(
                "DNS-NO-SPF-OBSERVED",
                "SPF record not observed",
                "info",
                "low",
                f"No TXT value beginning with v=spf1 was returned for {base}.",
                "Confirm the domain's mail-sending policy and publish an SPF record if the domain sends email.",
                "DNS TXT",
            )
        )

    dmarc_name = f"_dmarc.{base}"
    dmarc = next(
        (item.values for item in records if item.name == dmarc_name and item.record_type == "TXT"),
        [],
    )
    if not any("v=dmarc1" in value.lower() for value in dmarc):
        findings.append(
            _finding(
                "DNS-NO-DMARC-OBSERVED",
                "DMARC record not observed",
                "info",
                "low",
                f"No DMARC TXT policy was returned for {dmarc_name}.",
                "If the domain handles email, review a staged DMARC policy with its mail administrator.",
                "DNS TXT",
            )
        )

    caa = by_type.get((base, "CAA"))
    if caa is not None and caa.status == "no_answer":
        findings.append(
            _finding(
                "DNS-NO-CAA-OBSERVED",
                "CAA record not observed",
                "info",
                "low",
                f"No CAA records were returned for {base}.",
                "Review whether certificate issuance should be limited to approved certificate authorities.",
                "DNS CAA",
            )
        )
    return findings


def _http_findings(result: TargetResult) -> list[Finding]:
    observation = result.http
    if observation is None:
        return []
    findings: list[Finding] = []
    if observation.error_type == "TLSVerificationError":
        findings.append(
            _finding(
                "HTTP-TLS-VERIFICATION-FAILED",
                "HTTPS certificate could not be verified",
                "info",
                "medium",
                "The HTTPS request failed the client's default certificate verification.",
                "Review certificate validity, trust chain, and hostname on the intended service.",
                "HTTP/TLS",
            )
        )
        return findings
    if observation.status_code is None:
        return findings

    headers = {key.lower() for key in observation.headers}
    expected = {
        "content-security-policy": "Review a policy that matches the application's loaded resources.",
        "x-content-type-options": "Set X-Content-Type-Options: nosniff where browser content is served.",
        "referrer-policy": "Choose a Referrer-Policy suited to the application's privacy needs.",
        "permissions-policy": "Restrict browser features that the application does not use.",
    }
    if result.origin.startswith("https://"):
        expected["strict-transport-security"] = "After confirming HTTPS coverage, consider a suitable HSTS policy."
    for header, recommendation in expected.items():
        if header not in headers:
            findings.append(
                _finding(
                    f"HTTP-MISSING-{header.upper().replace('-', '_')}",
                    f"{header} response header not observed",
                    "low",
                    "low",
                    f"The root response did not include {header}.",
                    recommendation,
                    "HTTP response headers",
                )
            )

    for cookie in observation.cookies:
        missing: list[str] = []
        if result.origin.startswith("https://") and not cookie.secure:
            missing.append("Secure")
        if not cookie.http_only:
            missing.append("HttpOnly")
        if not cookie.same_site:
            missing.append("SameSite")
        if missing:
            findings.append(
                _finding(
                    "HTTP-COOKIE-ATTRIBUTES",
                    "Cookie security attributes need review",
                    "low",
                    "medium",
                    f"Cookie {cookie.name!r} did not include: {', '.join(missing)}. Cookie values were not stored.",
                    "Set cookie attributes according to whether the cookie is a session or cross-site token.",
                    "Set-Cookie attributes",
                )
            )

    expires_at = observation.tls.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expiry = datetime.fromtimestamp(cert_time_to_seconds(expires_at), UTC)
        except (OverflowError, ValueError):
            expiry = None
        if expiry is not None and datetime.now(UTC) <= expiry <= datetime.now(UTC) + timedelta(days=30):
            findings.append(
                _finding(
                    "TLS-CERT-EXPIRING",
                    "TLS certificate expires within 30 days",
                    "low",
                    "high",
                    f"The verified certificate is recorded as expiring at {expiry.isoformat()}.",
                    "Schedule certificate renewal and verify automated renewal monitoring.",
                    "TLS certificate metadata",
                )
            )
    return findings


def analyze_target(result: TargetResult) -> list[Finding]:
    result.findings = _dns_findings(result.dns) + _http_findings(result)
    return result.findings


def analyze(results: list[TargetResult]) -> None:
    for result in results:
        analyze_target(result)
