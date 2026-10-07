import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from gate_us_lite.http import FetchError, _SafeRedirects, fetch


class TestFetch(unittest.TestCase):
    def test_failure_reports_http_status_and_hides_the_query(self):
        denied = urllib.error.HTTPError("https://example.com/a", 403, "Forbidden", {}, None)
        self.addCleanup(denied.close)
        with patch.object(urllib.request.OpenerDirector, "open", side_effect=denied):
            with self.assertRaises(FetchError) as ctx:
                fetch("https://example.com/a?key=secret", retries=0)
        self.assertEqual(str(ctx.exception), "fetch failed: https://example.com/a?<redacted>: HTTPError 403")
        self.assertEqual(ctx.exception.reason, "HTTPError 403")

    def test_failure_without_status_reports_the_exception_type(self):
        with patch.object(urllib.request.OpenerDirector, "open", side_effect=TimeoutError()):
            with self.assertRaises(RuntimeError) as ctx:
                fetch("https://example.com/a", retries=0)
        self.assertTrue(str(ctx.exception).endswith(": TimeoutError"))

    def test_proxy_is_applied_to_https_requests_only_when_given(self):
        for proxy, expected in (("http://127.0.0.1:9", {"https": "http://127.0.0.1:9"}), (None, None)):
            with self.subTest(proxy=proxy), patch.object(urllib.request, "build_opener", wraps=urllib.request.build_opener) as build:
                with patch.object(urllib.request.OpenerDirector, "open", side_effect=TimeoutError()):
                    with self.assertRaises(RuntimeError):
                        fetch("https://example.com/a", retries=0, proxy=proxy)
                handlers = [h for h in build.call_args.args if h is not _SafeRedirects]
                if expected is None:
                    self.assertEqual(handlers, [])
                else:
                    self.assertEqual([h.proxies for h in handlers], [expected])

    def test_only_https_urls_are_fetched(self):
        for url in ("http://example.com/a", "ftp://example.com/a", "file:///etc/passwd", "example.com/a"):
            with self.subTest(url), patch.object(urllib.request.OpenerDirector, "open") as opened:
                with self.assertRaisesRegex(ValueError, "only https"):
                    fetch(url)
                opened.assert_not_called()


class TestRedirects(unittest.TestCase):
    def redirect(self, target: str):
        headers = {"Authorization": "Bearer secret", "Key": "secret", "Accept": "application/json", "User-Agent": "agent"}
        request = urllib.request.Request("https://api.example/a", headers=headers)
        return _SafeRedirects().redirect_request(request, None, 302, "Found", {}, target)

    def test_headers_stay_with_the_origin_that_received_them(self):
        self.assertEqual(self.redirect("https://api.example/b").get_header("Authorization"), "Bearer secret")
        self.assertEqual(self.redirect("https://cdn.example/b").headers, {"Accept": "application/json", "User-agent": "agent"})

    def test_redirects_leaving_https_are_refused(self):
        for target in ("http://api.example/b", "ftp://api.example/b", "file:///etc/passwd"):
            with self.subTest(target), self.assertRaises(urllib.error.HTTPError) as refused:
                self.redirect(target)
            refused.exception.close()


if __name__ == "__main__":
    unittest.main()
