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


def fetch(url: str, *, headers: dict[str, str] | None = None, timeout: int = 20,
          retries: int = 2, max_bytes: int = 8_000_000) -> HTTPResponse:
    merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        merged.update(headers)
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=merged)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    raise RuntimeError(f"fetch failed: {safe_url}: {type(last).__name__ if last else 'unknown'}")
