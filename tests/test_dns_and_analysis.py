from __future__ import annotations

from types import SimpleNamespace

from webrecon import dns_collect
from webrecon.analyzer import analyze_target
from webrecon.models import DnsObservation, HttpObservation, TargetResult
from webrecon.scope import parse_target


class FakeRRSet(list):
    ttl = 300


class FakeResolver:
    def __init__(self, configure: bool = True) -> None:
        self.timeout = 0
        self.lifetime = 0

    def resolve(self, name, record_type, **kwargs):
        answers = {
            ("site.example", "A"): ["192.0.2.8"],
            ("site.example", "AAAA"): ["2001:db8::8"],
            ("site.example", "TXT"): ['"v=spf1 include:mail.example -all"'],
            ("_dmarc.site.example", "TXT"): ['"v=DMARC1; p=quarantine"'],
            ("site.example", "CAA"): ['0 issue "ca.example"'],
        }
        values = answers.get((name, record_type), [])
        return SimpleNamespace(rrset=FakeRRSet(SimpleNamespace(to_text=lambda v=value: v) for value in values))


def test_dns_collection_covers_common_records_and_dmarc(monkeypatch) -> None:
    monkeypatch.setattr(dns_collect.dns.resolver, "Resolver", FakeResolver)
    records = dns_collect.collect_dns(parse_target("site.example"), timeout=0.2)
    assert len(records) == 9
    assert next(item for item in records if item.record_type == "A").values == ["192.0.2.8"]
    assert any(item.name == "_dmarc.site.example" and item.status == "ok" for item in records)


def test_analysis_creates_dns_and_http_review_leads() -> None:
    target = TargetResult(
        target="https://site.example",
        origin="https://site.example",
        hostname="site.example",
        dns=[
            DnsObservation("site.example", "A", "ok", ["192.0.2.8"]),
            DnsObservation("site.example", "TXT", "no_answer"),
            DnsObservation("_dmarc.site.example", "TXT", "no_answer"),
            DnsObservation("site.example", "CAA", "no_answer"),
        ],
        http=HttpObservation(url="https://site.example/", status_code=200),
    )
    findings = analyze_target(target)
    rule_ids = {finding.rule_id for finding in findings}
    assert "DNS-NO-SPF-OBSERVED" in rule_ids
    assert "DNS-NO-DMARC-OBSERVED" in rule_ids
    assert "DNS-NO-CAA-OBSERVED" in rule_ids
    assert "HTTP-MISSING-STRICT_TRANSPORT_SECURITY" in rule_ids
