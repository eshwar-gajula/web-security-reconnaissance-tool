from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver

from .models import DnsObservation, TargetSpec

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")


def _query(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
    timeout: float,
) -> DnsObservation:
    try:
        answer = resolver.resolve(
            name,
            record_type,
            lifetime=timeout,
            raise_on_no_answer=False,
        )
        rrset = answer.rrset
        values = [item.to_text() for item in rrset] if rrset else []
        return DnsObservation(
            name=name,
            record_type=record_type,
            status="ok" if values else "no_answer",
            values=values[:50],
            ttl=int(rrset.ttl) if rrset else None,
        )
    except dns.resolver.NXDOMAIN:
        return DnsObservation(name=name, record_type=record_type, status="nxdomain")
    except dns.resolver.NoAnswer:
        return DnsObservation(name=name, record_type=record_type, status="no_answer")
    except dns.exception.Timeout:
        return DnsObservation(name=name, record_type=record_type, status="timeout")
    except dns.resolver.NoNameservers:
        return DnsObservation(name=name, record_type=record_type, status="resolver_error")
    except (dns.exception.DNSException, OSError, ValueError) as exc:
        return DnsObservation(
            name=name,
            record_type=record_type,
            status="error",
            detail=type(exc).__name__,
        )


def collect_dns(target: TargetSpec, timeout: float = 2.0) -> list[DnsObservation]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        address = ipaddress.ip_address(target.hostname)
    except ValueError:
        base_name = target.hostname
        records = [_query(resolver, base_name, kind, timeout) for kind in RECORD_TYPES]
        records.append(_query(resolver, f"_dmarc.{base_name}", "TXT", timeout))
        return records

    return [_query(resolver, address.reverse_pointer, "PTR", timeout)]
