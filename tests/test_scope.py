from __future__ import annotations

import pytest

from webrecon.models import TargetSpec
from webrecon.scope import TargetError, load_targets, normalize_endpoint, parse_target, same_origin_url


def test_parse_target_normalizes_host_and_default_scheme() -> None:
    target = parse_target("EXAMPLE.COM")
    assert target.scheme == "https"
    assert target.hostname == "example.com"
    assert target.port == 443
    assert target.origin == "https://example.com"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com/?token=secret",
        "https://example.com:22",
    ],
)
def test_rejects_unsafe_or_out_of_scope_target_forms(value: str) -> None:
    with pytest.raises(TargetError):
        parse_target(value)


def test_target_file_deduplicates_origins_and_supports_comments(tmp_path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("# test\nexample.com\nhttps://example.com/\n", encoding="utf-8")
    targets = load_targets([], str(path))
    assert [target.origin for target in targets] == ["https://example.com"]


def test_same_origin_and_endpoint_query_redaction() -> None:
    target = parse_target("https://example.com")
    assert same_origin_url("https://example.com:443/docs", target)
    assert not same_origin_url("https://other.example.com/docs", target)
    assert normalize_endpoint("https://example.com/docs?token=private#part", target) == "/docs"
    assert normalize_endpoint("https://other.example.com/docs", target) is None


def test_non_default_port_is_limited_to_supported_web_ports() -> None:
    target = TargetSpec("http://127.0.0.1:8080", "http", "127.0.0.1", 8080)
    assert target.origin == "http://127.0.0.1:8080"
