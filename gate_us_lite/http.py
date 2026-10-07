from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass

USER_AGENT = "gate-us-lite/0.1 (+personal multi-source selector)"


@dataclass(slots=True)
class HTTPResponse:
    body: bytes
    status: int
    headers: dict[str, str]
    url: str

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text())


class FetchError(RuntimeError):
    """A request that failed after its last retry; `reason` names the final failure, e.g. "HTTPError 410"."""

    def __init__(self, url: str, reason: str):
        super().__init__(f"fetch failed: {url}: {reason}")
        self.reason = reason


def _describe(exc: Exception | None) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTPError {exc.code}"
    return type(exc).__name__ if exc else "unknown"


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Follow https redirects only, and never hand request headers (API keys) to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise urllib.error.HTTPError(req.full_url, code, "redirect to a non-https URL refused", headers, fp)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and target.netloc != urllib.parse.urlsplit(req.full_url).netloc:
            redirected.headers = {k: v for k, v in redirected.headers.items() if k.lower() in {"user-agent", "accept"}}
        return redirected


def fetch(url: str, *, headers: dict[str, str] | None = None, timeout: float = 20,
          retries: int = 2, max_bytes: int = 8_000_000, proxy: str | None = None) -> HTTPResponse:
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme != "https":
        raise ValueError(f"only https URLs are fetched, not {scheme or 'scheme-less'} ones")
    merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        merged.update(headers)
    opener = urllib.request.build_opener(_SafeRedirects, *([urllib.request.ProxyHandler({"https": proxy})] if proxy else []))
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=merged)
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ValueError(f"response exceeds {max_bytes} bytes")
                return HTTPResponse(body, getattr(resp, "status", 200), dict(resp.headers), resp.geturl())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
            last = exc
            if attempt < retries:
                time.sleep(0.7 * (attempt + 1))
    parts=urllib.parse.urlsplit(url)
    safe_url=urllib.parse.urlunsplit((parts.scheme,parts.netloc,parts.path,"<redacted>" if parts.query else "",parts.fragment))
    raise FetchError(safe_url, _describe(last))
