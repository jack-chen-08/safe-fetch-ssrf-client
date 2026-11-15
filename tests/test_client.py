"""规则 4-8 的主流程单测：注入桩传输层，全程不触网。

对照验收标准：
  1) 解析到 10.0.0.5 / 169.254.169.254 → SSRF_BLOCKED
  2) 重定向到白名单外主机 / 内网地址 → 被拦截
  3) 解压后 >10MB 的 gzip → TOO_LARGE（且是「中断」而非读完再判）
  4) 静态检查（见 test_static_guard.py + scripts/check_no_bypass.py）
"""

from __future__ import annotations

import gzip
import logging
import unittest

from intel.safe_fetch import ErrorCode, FetchBlocked, SafeFetchConfig, Source, safe_fetch
from intel.safe_fetch.client import _build_request
from intel.safe_fetch.policy import validate_target

MEG = 1024 * 1024
SOURCE = Source(name="example-feed", allowed_hosts=("example.com", "feeds.example.com"))


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", chunk_size=64 * 1024):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body
        self._chunk = chunk_size

    def iter_raw(self):
        for i in range(0, len(self._body), self._chunk):
            yield self._body[i : i + self._chunk]


class FakeTransport:
    """按 URL 返回预设响应，并记录每次实际发起的请求（用于证明「每跳都重新校验」）。"""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, target, cfg, remaining):
        self.calls.append(target.url)
        for matcher, response in self.routes:
            if matcher(target):
                return response
        raise AssertionError(f"桩传输层未配置该目标：{target.url}")


def resolver(mapping):
    def _r(host, port):
        if host not in mapping:
            raise OSError(f"桩 DNS 未知主机 {host}")
        return mapping[host]

    return _r


PUBLIC_DNS = resolver({"example.com": ["93.184.216.34"], "feeds.example.com": ["93.184.216.35"]})

HTML = FakeResponse(200, {"Content-Type": "text/html; charset=utf-8"}, b"<html>hi</html>")


class TestHappyPath(unittest.TestCase):
    def test_html_ok(self):
        transport = FakeTransport([(lambda t: True, HTML)])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        result = safe_fetch("https://example.com/brief", SOURCE, cfg)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content_type, "text/html")
        self.assertEqual(result.body, b"<html>hi</html>")
        self.assertEqual(result.resolved_ips, ("93.184.216.34",))
        self.assertEqual(result.redirects, ())
        self.assertEqual(len(transport.calls), 1)

    def test_pdf_and_xml_accepted(self):
        for ctype, body in (
            ("application/pdf", b"%PDF-1.7"),
            ("application/rss+xml", b"<rss/>"),
            ("application/atom+xml", b"<feed/>"),
            ("application/xhtml+xml", b"<html/>"),
            ("application/xml", b"<x/>"),
            ("text/xml", b"<x/>"),
        ):
            with self.subTest(ctype=ctype):
                transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": ctype}, body))])
                cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
                self.assertEqual(safe_fetch("https://example.com/a", SOURCE, cfg).content_type, ctype)

    def test_gzip_decoded(self):
        payload = "<html>" + ("x" * 5000) + "</html>"
        compressed = gzip.compress(payload.encode())
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, compressed))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        result = safe_fetch("https://example.com/gz", SOURCE, cfg)
        self.assertEqual(result.body, payload.encode())
        self.assertEqual(result.encoding_used, "gzip")
        self.assertEqual(result.raw_bytes, len(compressed))
        self.assertEqual(result.decoded_bytes, len(payload.encode()))


class TestContentType(unittest.TestCase):
    def test_image_rejected(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "image/jpeg"}, b"\xff\xd8"))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/a.jpg", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_CONTENT_TYPE)

    def test_missing_content_type_rejected(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {}, b"data"))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/x", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_CONTENT_TYPE)

    def test_octet_stream_rejected(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "application/octet-stream"}, b"z"))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/z", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_CONTENT_TYPE)


class TestRedirects(unittest.TestCase):
    """验收标准 2：每一跳重新执行 1-4 的全部校验。"""

    def test_redirect_to_host_outside_allowlist_blocked(self):
        transport = FakeTransport(
            [(lambda t: t.host == "example.com", FakeResponse(302, {"Location": "https://evil.com/payload"}))]
        )
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/start", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)
        self.assertEqual(ctx.exception.host, "evil.com")
        # 第二跳在策略层就被拦下，未真正发出请求
        self.assertEqual(len(transport.calls), 1)

    def test_redirect_to_internal_ip_blocked(self):
        """白名单内域名，但桩 DNS 把它解析到内网 → SSRF_BLOCKED。"""
        dns = resolver({"example.com": ["93.184.216.34"], "feeds.example.com": ["10.0.0.5"]})
        transport = FakeTransport(
            [(lambda t: t.host == "example.com", FakeResponse(302, {"Location": "https://feeds.example.com/internal"}))]
        )
        cfg = SafeFetchConfig(resolver=dns, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/start", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)
        self.assertEqual(ctx.exception.resolved_ips, ("10.0.0.5",))

    def test_redirect_to_metadata_ip_blocked(self):
        dns = resolver({"example.com": ["93.184.216.34"]})
        transport = FakeTransport(
            [(lambda t: t.host == "example.com", FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/iam/"}))]
        )
        cfg = SafeFetchConfig(resolver=dns, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/start", SOURCE, cfg)
        # IP 字面量主机不在白名单内 → 在主机闸就被拒；两种码都代表拦截成功
        self.assertIn(ctx.exception.code, {ErrorCode.HOST_NOT_ALLOWED, ErrorCode.SSRF_BLOCKED})

    def test_redirect_to_private_ip_in_allowlist_reaches_ip_gate(self):
        """把 IP 显式写进白名单，验证 IP 闸门本身也拦得住。"""
        src = Source(name="naive", allowed_hosts=("example.com", "169.254.169.254"))
        transport = FakeTransport(
            [(lambda t: t.host == "example.com", FakeResponse(302, {"Location": "http://169.254.169.254/"}))]
        )
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/start", src, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)

    def test_three_redirects_allowed(self):
        transport = FakeTransport(
            [
                (lambda t: t.url == "https://example.com/a", FakeResponse(302, {"Location": "/b"})),
                (lambda t: t.url == "https://example.com/b", FakeResponse(301, {"Location": "/c"})),
                (lambda t: t.url == "https://example.com/c", FakeResponse(307, {"Location": "https://feeds.example.com/d"})),
                (lambda t: t.url == "https://feeds.example.com/d", HTML),
            ]
        )
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        result = safe_fetch("https://example.com/a", SOURCE, cfg)
        self.assertEqual(result.url, "https://feeds.example.com/d")
        self.assertEqual(
            result.redirects,
            ("https://example.com/b", "https://example.com/c", "https://feeds.example.com/d"),
        )
        self.assertEqual(len(transport.calls), 4)

    def test_four_redirects_rejected(self):
        transport = FakeTransport(
            [
                (lambda t: t.url.endswith("/a"), FakeResponse(302, {"Location": "/b"})),
                (lambda t: t.url.endswith("/b"), FakeResponse(302, {"Location": "/c"})),
                (lambda t: t.url.endswith("/c"), FakeResponse(302, {"Location": "/d"})),
                (lambda t: t.url.endswith("/d"), FakeResponse(302, {"Location": "/e"})),
                (lambda t: t.url.endswith("/e"), HTML),
            ]
        )
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/a", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.TOO_MANY_REDIRECTS)
        self.assertEqual(len(transport.calls), 4)  # 首跳 + 3 跳跟随，第 4 次重定向被拒

    def test_redirect_without_location_returns_as_is(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(302, {"Content-Type": "text/html"}, b"no-loc"))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        result = safe_fetch("https://example.com/r", SOURCE, cfg)
        self.assertEqual(result.status_code, 302)


class TestSizeLimits(unittest.TestCase):
    """验收标准 3：解压后 >10MB 立即中断。"""

    def test_gzip_bomb_rejected(self):
        bomb = gzip.compress(b"\0" * (11 * MEG))
        self.assertLess(len(bomb), MEG)  # 压缩态远小于 10MB，说明拦的是解压后体积
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, bomb))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/bomb", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.TOO_LARGE)
        self.assertIn("解压后", ctx.exception.message)

    def test_raw_body_over_limit_rejected(self):
        big = b"x" * (10 * MEG + 1)
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "text/html"}, big))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/big", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.TOO_LARGE)

    def test_exactly_at_limit_allowed(self):
        exact = b"x" * (10 * MEG)
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "text/html"}, exact))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport)
        result = safe_fetch("https://example.com/exact", SOURCE, cfg)
        self.assertEqual(result.decoded_bytes, 10 * MEG)

    def test_limit_is_configurable(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(200, {"Content-Type": "text/html"}, b"y" * 100))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport, max_body_bytes=50)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/s", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.TOO_LARGE)


class TestTimeouts(unittest.TestCase):
    def test_total_budget_exhausted(self):
        transport = FakeTransport([(lambda t: True, HTML)])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport, total_timeout=0)
        with self.assertRaises(FetchBlocked) as ctx:
            safe_fetch("https://example.com/", SOURCE, cfg)
        self.assertEqual(ctx.exception.code, ErrorCode.TIMEOUT)
        self.assertEqual(transport.calls, [])  # 预算耗尽时根本不应发出请求


class TestSecurityLog(unittest.TestCase):
    """被拦截的请求必须写安全日志：URL、解析 IP、原因。"""

    def setUp(self):
        self.records = []
        self.logger = logging.getLogger(f"test.safe_fetch.{id(self)}")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.Handler()
        handler.emit = self.records.append
        self.logger.addHandler(handler)
        self.addCleanup(self.logger.removeHandler, handler)

    def test_blocked_request_logged_with_ip_and_reason(self):
        dns = resolver({"example.com": ["10.0.0.5"]})
        cfg = SafeFetchConfig(resolver=dns, transport=FakeTransport([]), logger=self.logger)
        with self.assertRaises(FetchBlocked):
            safe_fetch("https://example.com/secret", SOURCE, cfg)

        self.assertEqual(len(self.records), 1)
        record = self.records[0]
        self.assertEqual(record.code, ErrorCode.SSRF_BLOCKED.value)
        self.assertEqual(record.url, "https://example.com/secret")
        self.assertEqual(record.host, "example.com")
        self.assertEqual(record.resolved_ips, ["10.0.0.5"])
        self.assertIn("10.0.0.5", record.reason)
        self.assertEqual(record.sourcename if hasattr(record, "sourcename") else record.source, "example-feed")

    def test_redirect_block_logged(self):
        transport = FakeTransport([(lambda t: True, FakeResponse(302, {"Location": "https://evil.com/x"}))])
        cfg = SafeFetchConfig(resolver=PUBLIC_DNS, transport=transport, logger=self.logger)
        with self.assertRaises(FetchBlocked):
            safe_fetch("https://example.com/go", SOURCE, cfg)
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0].code, ErrorCode.HOST_NOT_ALLOWED.value)
        self.assertEqual(self.records[0].host, "evil.com")


class TestRequestShape(unittest.TestCase):
    """规则 4 + 8：Host 用域名、不带 Cookie/认证头、不带代理头。"""

    def test_no_cookie_or_auth_headers(self):
        target = validate_target("https://example.com/path?q=1", ("example.com",), PUBLIC_DNS)
        request = _build_request(target, SafeFetchConfig()).decode("ascii")
        lowered = request.lower()
        for forbidden in ("cookie", "authorization", "proxy-authorization", "proxy-connection"):
            self.assertNotIn(forbidden, lowered)
        self.assertNotIn("x-forwarded", lowered)

    def test_host_header_uses_domain_not_ip(self):
        target = validate_target("https://example.com/path?q=1", ("example.com",), PUBLIC_DNS)
        request = _build_request(target, SafeFetchConfig()).decode("ascii")
        self.assertIn("Host: example.com\r\n", request)
        self.assertIn("GET /path?q=1 HTTP/1.1", request)
        self.assertNotIn("93.184.216.34", request)

    def test_non_default_port_in_host_header(self):
        dns = resolver({"example.com": ["93.184.216.34"]})
        target = validate_target("https://example.com:443/a", ("example.com",), dns)
        self.assertEqual(target.host_header, "example.com")
        target80 = validate_target("http://example.com:80/a", ("example.com",), dns)
        self.assertEqual(target80.host_header, "example.com")


if __name__ == "__main__":
    unittest.main()
