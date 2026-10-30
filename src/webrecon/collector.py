from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .dns_collect import collect_dns
from .http_collect import collect_http
from .models import TargetResult, TargetSpec

MAX_TARGET_WORKERS = 3


def collect_target(target: TargetSpec, timeout: float, skip_dns: bool = False, skip_http: bool = False) -> TargetResult:
    result = TargetResult(
        target=target.original,
        origin=target.origin,
        hostname=target.hostname,
    )
    if not skip_dns:
        try:
            result.dns = collect_dns(target, min(timeout, 3.0))
        except Exception as exc:
            result.warnings.append(f"DNS collection failed: {type(exc).__name__}.")
    if not skip_http:
        try:
            result.http, result.endpoints = collect_http(target, timeout)
        except Exception as exc:
            result.warnings.append(f"HTTP collection failed: {type(exc).__name__}.")
    return result


def collect(
    targets: list[TargetSpec],
    timeout: float,
    skip_dns: bool = False,
    skip_http: bool = False,
) -> list[TargetResult]:
    results: dict[str, TargetResult] = {}
    with ThreadPoolExecutor(max_workers=min(MAX_TARGET_WORKERS, len(targets))) as executor:
        futures = {executor.submit(collect_target, target, timeout, skip_dns, skip_http): target for target in targets}
        for future in as_completed(futures):
            target = futures[future]
            results[target.origin] = future.result()
    return [results[target.origin] for target in targets]
