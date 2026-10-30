from __future__ import annotations

import json
import re
import time
from collections import OrderedDict
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

from .models import CookieAssessment, EndpointObservation, HttpObservation, TargetSpec
from .scope import normalize_endpoint, same_origin_url

MAX_BODY_BYTES = 256 * 1024
MAX_ENDPOINTS = 256
MAX_PAGE_LINKS = 100
MAX_SCHEMA_PATHS = 50
MAX_ROBOTS_HINTS = 20
MAX_SITEMAP_HINTS = 50
MAX_COOKIES = 20
REQUEST_GAP_SECONDS = 0.15
SELECTED_HEADERS = (
    "server",
    "x-powered-by",
    "via",
    "content-type",
    "content-length",
    "cache-control",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
WELL_KNOWN_ENDPOINTS = (
    ("/robots.txt", "GET", "robots"),
    ("/sitemap.xml", "GET", "sitemap"),
    ("/.well-known/security.txt", "HEAD", "security-txt"),
    ("/openapi.json", "GET", "api-schema"),
    ("/swagger.json", "GET", "api-schema"),
    ("/swagger/v1/swagger.json", "GET", "api-schema"),
    ("/openapi.yaml", "HEAD", "api-schema"),
    ("/api-docs", "GET", "api-schema"),
    ("/docs", "HEAD", "api-documentation"),
    ("/graphql", "HEAD", "graphql-route"),
)
TECH_SIGNATURES = {
    "WordPress": re.compile(r"wp-content|wp-includes|wordpress", re.I),
    "Drupal": re.compile(r"drupal-settings-json|/sites/default/files/", re.I),
    "Joomla": re.compile(r"/media/system/js/|joomla!|generator.{0,30}joomla", re.I),
    "Django": re.compile(r"csrftoken|django", re.I),
    "Laravel": re.compile(r"laravel_session|laravel", re.I),
    "Ruby on Rails": re.compile(r"_rails|csrf-token.{0,80}rails", re.I),
    "Next.js": re.compile(r"__next|/_next/|next\.js", re.I),
    "Nuxt": re.compile(r"__nuxt|/_nuxt/", re.I),
    "React": re.compile(r"react(?:\.production)?(?:\.min)?\.js|data-reactroot", re.I),
    "Vue.js": re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{6,}", re.I),
    "Angular": re.compile(r"ng-version=|angular(?:\.min)?\.js", re.I),
    "Express": re.compile(r"x-powered-by.{0,20}express", re.I),
    "PHP": re.compile(r"x-powered-by.{0,20}php|phpsessid", re.I),
    "ASP.NET": re.compile(r"asp\.net|aspnet_sessionid|x-powered-by.{0,30}\.net", re.I),
    "nginx": re.compile(r"^nginx(?:/|$)", re.I),
    "Apache HTTP Server": re.compile(r"^apache(?:/|$)", re.I),
    "Microsoft IIS": re.compile(r"^microsoft-iis(?:/|$)", re.I),
    "Cloudflare": re.compile(r"cloudflare|cf-ray", re.I),
}


class _PageParser(HTMLParser):
    def __init__(self, target: TargetSpec) -> None:
        super().__init__(convert_charrefs=True)
        self.target = target
        self.links: OrderedDict[str, set[str]] = OrderedDict()
        self.meta_generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs if value is not None}
        candidates: list[tuple[str, str]] = []
        if tag.lower() == "a" and attributes.get("href"):
            candidates.append((attributes["href"], "html-link"))
        if tag.lower() == "script" and attributes.get("src"):
            candidates.append((attributes["src"], "script-src"))
        if tag.lower() == "link" and attributes.get("href"):
            candidates.append((attributes["href"], "link-href"))

        for raw_url, source in candidates:
            absolute = urljoin(self.target.root_url, raw_url)
            path = normalize_endpoint(absolute, self.target)
            if path and len(self.links) < MAX_PAGE_LINKS:
                self.links.setdefault(path, set()).add(source)

        if tag.lower() == "meta" and attributes.get("name", "").lower() == "generator":
            content = attributes.get("content", "").strip()
            if content:
                self.meta_generator = content[:120]


def _selected_headers(headers: requests.structures.CaseInsensitiveDict) -> dict[str, str]:
    collected: dict[str, str] = {}
    for key in SELECTED_HEADERS:
        value = headers.get(key)
        if value:
            collected[key] = " ".join(value.replace("\r", " ").replace("\n", " ").split())[:512]
    return collected


def _cookie_assessments(response: requests.Response) -> list[CookieAssessment]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
    else:
        combined = response.headers.get("Set-Cookie", "")
        values = [combined] if combined else []

    results: list[CookieAssessment] = []
    for value in values[:MAX_COOKIES]:
        parts = [part.strip() for part in value.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()[:80]
        if not name:
            continue
        attrs = {
            part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip() if "=" in part else ""
            for part in parts[1:]
        }
        results.append(
            CookieAssessment(
                name=name,
                secure="secure" in attrs,
                http_only="httponly" in attrs,
                same_site=attrs.get("samesite") or None,
            )
        )
    return results


def _tls_details(response: requests.Response) -> dict[str, object]:
    raw = response.raw
    connection = getattr(raw, "connection", None) or getattr(raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        return {}
    try:
        certificate = sock.getpeercert()
        subject_alt_names = [
            value for kind, value in certificate.get("subjectAltName", []) if kind in {"DNS", "IP Address"}
        ]
        not_after = certificate.get("notAfter")
        issuer = ", ".join(f"{key}={value}" for group in certificate.get("issuer", []) for key, value in group)[:256]
        return {
            "verified": True,
            "tls_version": sock.version(),
            "cipher": sock.cipher()[0] if sock.cipher() else None,
            "issuer": issuer or None,
            "expires_at": not_after,
            "subject_alt_names": subject_alt_names[:50],
        }
    except (AttributeError, OSError, ValueError):
        return {"verified": True, "details_available": False}


def _read_limited(response: requests.Response, limit: int = MAX_BODY_BYTES) -> tuple[bytes, bool]:
    body = bytearray()
    truncated = False
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        remaining = limit - len(body)
        body.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
            break
        if len(body) >= limit:
            truncated = True
            break
    return bytes(body), truncated


def _technologies(
    headers: dict[str, str],
    body_text: str,
    meta_generator: str | None,
    cookie_names: list[str],
) -> list[str]:
    evidence = "\n".join([*headers.values(), *cookie_names, body_text[:MAX_BODY_BYTES], meta_generator or ""])
    return sorted(name for name, signature in TECH_SIGNATURES.items() if signature.search(evidence))


def _same_origin_redirect(response: requests.Response, target: TargetSpec) -> bool | None:
    location = response.headers.get("Location")
    if not location:
        return None
    return same_origin_url(urljoin(target.root_url, location), target)


def _fetch(
    session: requests.Session,
    target: TargetSpec,
    path: str,
    method: str,
    timeout: float,
    read_body: bool,
) -> tuple[requests.Response | None, bytes, bool, str | None, dict[str, object]]:
    url = f"{target.origin}{path}"
    try:
        response = session.request(
            method,
            url,
            headers={"User-Agent": "webrecon/1.0.0 (authorized security reconnaissance)"},
            timeout=(timeout, timeout),
            allow_redirects=False,
            verify=True,
            stream=True,
        )
        tls = _tls_details(response) if target.scheme == "https" else {}
        body, truncated = _read_limited(response) if read_body else (b"", False)
        return response, body, truncated, None, tls
    except requests.exceptions.SSLError:
        return None, b"", False, "TLSVerificationError", {}
    except requests.exceptions.Timeout:
        return None, b"", False, "Timeout", {}
    except requests.exceptions.RequestException as exc:
        return None, b"", False, type(exc).__name__, {}


def _add_endpoint(
    endpoints: OrderedDict[str, EndpointObservation],
    path: str,
    method: str,
    source: str,
    status: int | None = None,
    probed: bool = False,
    content_type: str | None = None,
    content_length: int | None = None,
    error_type: str | None = None,
) -> None:
    existing = endpoints.get(path)
    if existing is None:
        if len(endpoints) >= MAX_ENDPOINTS:
            return
        endpoints[path] = EndpointObservation(
            path=path,
            method=method,
            status_code=status,
            discovered_by=[source],
            probed=probed,
            content_type=content_type,
            content_length=content_length,
            error_type=error_type,
        )
    else:
        if source not in existing.discovered_by:
            existing.discovered_by.append(source)
        if probed:
            existing.method = method
            existing.status_code = status
            existing.probed = True
            existing.content_type = content_type
            existing.content_length = content_length
            existing.error_type = error_type


def _schema_paths(body: bytes, content_type: str) -> list[str]:
    if "json" not in content_type.lower():
        return []
    try:
        value = json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, dict):
        return []
    return [path for path in paths if isinstance(path, str)][:MAX_SCHEMA_PATHS]


def _robots_paths(body: bytes) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for line in body.decode("utf-8", errors="replace").splitlines()[:5000]:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value.startswith("/"):
            results.append((value.split("?", 1)[0][:512], "robots-disallow"))
        elif key == "sitemap" and value:
            results.append((value, "robots-sitemap"))
        if len(results) >= MAX_ROBOTS_HINTS:
            break
    return results


def _sitemap_paths(body: bytes) -> list[str]:
    # Regex over a small response avoids parsing untrusted XML with an entity-capable parser.
    matches = re.findall(rb"<loc\b[^>]*>\s*(.*?)\s*</loc\s*>", body, flags=re.IGNORECASE | re.DOTALL)
    return [unescape(value.decode("utf-8", errors="replace").strip()) for value in matches[:MAX_SITEMAP_HINTS]]


def collect_http(target: TargetSpec, timeout: float = 5.0) -> tuple[HttpObservation, list[EndpointObservation]]:
    endpoints: OrderedDict[str, EndpointObservation] = OrderedDict()
    session = requests.Session()
    session.trust_env = False
    observation = HttpObservation(url=target.root_url, status_code=None)
    try:
        response, body, truncated, error, tls = _fetch(session, target, "/", "GET", timeout, True)
        if error:
            observation.error_type = error
            return observation, []
        assert response is not None
        with response:
            observation.status_code = response.status_code
            observation.headers = _selected_headers(response.headers)
            observation.cookies = _cookie_assessments(response)
            observation.redirect_same_origin = _same_origin_redirect(response, target)
            observation.response_bytes_sampled = len(body)
            observation.body_truncated = truncated
            observation.tls = tls
            content_type = response.headers.get("Content-Type", "")
            html_text = (
                body.decode(response.encoding or "utf-8", errors="replace") if "html" in content_type.lower() else ""
            )
            parser = _PageParser(target)
            if html_text:
                try:
                    parser.feed(html_text)
                    parser.close()
                except (ValueError, AssertionError):
                    pass
            for path, sources in parser.links.items():
                for source in sorted(sources):
                    _add_endpoint(endpoints, path, "DISCOVERED", source)
            observation.technologies = _technologies(
                observation.headers,
                html_text,
                parser.meta_generator,
                [cookie.name for cookie in observation.cookies],
            )

        session.cookies.clear()
        time.sleep(REQUEST_GAP_SECONDS)

        for path, method, source in WELL_KNOWN_ENDPOINTS:
            if len(endpoints) >= MAX_ENDPOINTS:
                break
            response, endpoint_body, _truncated, error, _tls = _fetch(
                session,
                target,
                path,
                method,
                timeout,
                method == "GET" and source in {"robots", "sitemap", "api-schema"},
            )
            if error:
                _add_endpoint(endpoints, path, method, source, error_type=error)
                time.sleep(REQUEST_GAP_SECONDS)
                continue
            assert response is not None
            with response:
                content_type = response.headers.get("Content-Type", "")
                try:
                    content_length = int(response.headers.get("Content-Length", ""))
                except ValueError:
                    content_length = None
                _add_endpoint(
                    endpoints,
                    path,
                    method,
                    source,
                    status=response.status_code,
                    probed=True,
                    content_type=content_type[:256] or None,
                    content_length=content_length,
                )

            session.cookies.clear()
            if source == "robots":
                for value, kind in _robots_paths(endpoint_body):
                    if kind == "robots-sitemap":
                        url = urljoin(target.root_url, value)
                        endpoint_path = normalize_endpoint(url, target)
                    else:
                        endpoint_path = normalize_endpoint(f"{target.origin}{value}", target)
                    if endpoint_path:
                        _add_endpoint(endpoints, endpoint_path, "DISCOVERED", kind)
            elif source == "sitemap":
                for value in _sitemap_paths(endpoint_body):
                    endpoint_path = normalize_endpoint(urljoin(target.root_url, value), target)
                    if endpoint_path:
                        _add_endpoint(endpoints, endpoint_path, "DISCOVERED", "sitemap")
            elif source == "api-schema":
                for value in _schema_paths(endpoint_body, content_type):
                    endpoint_path = normalize_endpoint(urljoin(target.root_url, value), target)
                    if endpoint_path:
                        _add_endpoint(endpoints, endpoint_path, "DISCOVERED", "api-schema")
            time.sleep(REQUEST_GAP_SECONDS)

        observation.endpoint_count = len(endpoints)
        return observation, list(endpoints.values())
    finally:
        session.cookies.clear()
        session.close()
