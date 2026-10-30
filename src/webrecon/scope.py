from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from .models import TargetSpec

MAX_TARGETS = 25
MAX_TARGET_FILE_BYTES = 32 * 1024
MAX_TARGET_FILE_LINES = 100
ALLOWED_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9443}
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


class TargetError(ValueError):
    """Raised when a target is invalid or exceeds safe collection limits."""


def parse_target(value: str) -> TargetSpec:
    raw = value.strip()
    if not raw:
        raise TargetError("Target cannot be empty.")
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise TargetError("Only HTTP and HTTPS targets are supported.")
        if parts.username is not None or parts.password is not None:
            raise TargetError("Target URLs must not include usernames or passwords.")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise TargetError("Provide a site origin only; paths, queries, and fragments are not accepted.")
        if not parts.hostname:
            raise TargetError("Target URL must include a hostname.")
        hostname = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parts.port or (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, TargetError):
            raise
        raise TargetError(f"Invalid target URL: {raw!r}") from exc

    if len(hostname) > 253 or not hostname:
        raise TargetError("Target hostname is invalid or too long.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise TargetError(f"Invalid target hostname: {hostname!r}") from None
    if port not in ALLOWED_PORTS:
        raise TargetError(
            f"Port {port} is outside the supported web-port set: "
            + ", ".join(str(item) for item in sorted(ALLOWED_PORTS))
        )
    return TargetSpec(original=raw, scheme=scheme, hostname=hostname, port=port)


def load_targets(values: Iterable[str], target_file: str | None = None) -> list[TargetSpec]:
    raw_targets = [item.strip() for item in values if item and item.strip()]
    if target_file:
        try:
            raw = Path(target_file).read_bytes()
        except OSError as exc:
            raise TargetError(f"Could not read target file: {exc}") from exc
        if len(raw) > MAX_TARGET_FILE_BYTES:
            raise TargetError(f"Target file exceeds {MAX_TARGET_FILE_BYTES} bytes.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TargetError("Target file must be UTF-8 text.") from exc
        lines = text.splitlines()
        if len(lines) > MAX_TARGET_FILE_LINES:
            raise TargetError(f"Target file may contain at most {MAX_TARGET_FILE_LINES} lines.")
        raw_targets.extend(cleaned for line in lines if (cleaned := line.split("#", 1)[0].strip()))
    if not raw_targets:
        raise TargetError("Provide at least one --target or --target-file.")
    targets = [parse_target(item) for item in raw_targets]
    unique = {target.origin: target for target in targets}
    if len(unique) > MAX_TARGETS:
        raise TargetError(f"A scan may include at most {MAX_TARGETS} distinct origins.")
    return list(unique.values())


def same_origin_url(url: str, target: TargetSpec) -> bool:
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return False
        hostname = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except (UnicodeError, ValueError):
        return False
    return (parts.scheme.lower(), hostname, port) == (target.scheme, target.hostname, target.port)


def normalize_endpoint(url: str, target: TargetSpec, max_length: int = 512) -> str | None:
    if not same_origin_url(url, target):
        return None
    parts = urlsplit(url)
    path = parts.path or "/"
    if len(path) > max_length or "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return None
    # Never retain query strings or fragments; they can contain tokens or personal data.
    return path
