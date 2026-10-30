from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from webrecon import scope
from webrecon.cli import main
from webrecon.http_collect import collect_http
from webrecon.models import TargetSpec


class ReconHandler(BaseHTTPRequestHandler):
    calls: list[tuple[str, str]] = []
    sitemap_url = ""

    def _respond(self, code: int, content_type: str, body: bytes = b"", head: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/":
            self.send_header("Set-Cookie", "laravel_session=do-not-record-this-value; Path=/; HttpOnly")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        type(self).calls.append(("GET", path))
        if path == "/":
            body = (
                b'<html><head><meta name="generator" content="WordPress 6.4"></head>'
                b'<body><a href="/posts/one?token=secret-value">Post</a>'
                b'<a href="https://outside.example/private">Outside</a>'
                b'<script src="/wp-content/theme.js"></script></body></html>'
            )
            self._respond(200, "text/html; charset=utf-8", body)
        elif path == "/robots.txt":
            self._respond(
                200,
                "text/plain",
                f"User-agent: *\nDisallow: /private-area\nSitemap: {type(self).sitemap_url}\n".encode(),
            )
        elif path == "/sitemap.xml":
            body = (
                f"<urlset><url><loc>{type(self).sitemap_url.rsplit('/', 1)[0]}/public-post</loc></url>"
                "<url><loc>https://outside.example/no</loc></url></urlset>"
            ).encode()
            self._respond(200, "application/xml", body)
        elif path == "/openapi.json":
            self._respond(
                200, "application/json", json.dumps({"paths": {"/api/v1/status": {}, "/private-api": {}}}).encode()
            )
        else:
            self._respond(404, "text/plain", b"missing")

    def do_HEAD(self) -> None:
        path = urlsplit(self.path).path
        type(self).calls.append(("HEAD", path))
        self._respond(404, "text/plain", b"", head=True)

    def log_message(self, format: str, *args) -> None:
        return


def test_http_collect_is_bounded_and_keeps_endpoint_references_only() -> None:
    ReconHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReconHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    ReconHandler.sitemap_url = f"{origin}/sitemap.xml"
    target = TargetSpec(
        original=origin,
        scheme="http",
        hostname="127.0.0.1",
        port=server.server_address[1],
    )
    try:
        observation, endpoints = collect_http(target, timeout=1)
    finally:
        server.shutdown()
        worker.join(timeout=2)
        server.server_close()

    paths = {item.path for item in endpoints}
    requested = set(ReconHandler.calls)
    assert observation.status_code == 200
    assert "WordPress" in observation.technologies
    assert "Laravel" in observation.technologies
    assert observation.cookies[0].name == "laravel_session"
    assert "/posts/one" in paths
    assert "/private-area" in paths
    assert "/public-post" in paths
    assert "/api/v1/status" in paths
    assert "https://outside.example/private" not in paths
    assert ("GET", "/private-area") not in requested
    assert ("GET", "/posts/one") not in requested
    assert ("GET", "/api/v1/status") not in requested
    assert "do-not-record-this-value" not in json.dumps(observation.to_dict())
    assert not any("token=" in item.path for item in endpoints)


def test_cli_writes_a_complete_local_loopback_report(tmp_path, monkeypatch, capsys) -> None:
    ReconHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReconHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_address[1]
    monkeypatch.setattr(scope, "ALLOWED_PORTS", scope.ALLOWED_PORTS | {port})
    origin = f"http://127.0.0.1:{port}"
    ReconHandler.sitemap_url = f"{origin}/sitemap.xml"
    try:
        exit_code = main(
            [
                "--target",
                origin,
                "--skip-dns",
                "--authorized",
                "--output-dir",
                str(tmp_path),
                "--timeout",
                "1",
            ]
        )
    finally:
        server.shutdown()
        worker.join(timeout=2)
        server.server_close()
    assert exit_code == 0
    assert "Finished in" in capsys.readouterr().out
    assert len(list(tmp_path.glob("recon-*.json"))) == 1
    assert len(list(tmp_path.glob("recon-*.md"))) == 1
    assert len(list(tmp_path.glob("recon-*.csv"))) == 1
