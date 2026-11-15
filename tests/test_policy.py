"""规则 1/2/3 的策略层单测：全部离线，DNS 用桩函数（本地桩 DNS）。"""

from __future__ import annotations

import unittest

from intel.safe_fetch import ErrorCode, FetchBlocked, classify_ip, host_allowed, normalize_host, validate_target
from intel.safe_fetch.policy import ALLOWED_PORTS

ALLOWED = ("example.com", "feeds.example.com")


def stub_resolver(mapping):
    """本地桩 DNS：按主机名返回预设 IP 列表，完全不触网。"""

    def _resolve(host, port):
        if host not in mapping:
            raise OSError(f"桩 DNS 未知主机 {host}")
        return mapping[host]

    return _resolve


def ok_resolver(host, port):
    return ["93.184.216.34"]


class TestSchemeAndPort(unittest.TestCase):
    """规则 1：只允许 http/https，端口只允许 80/443。"""

    def test_ftp_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("ftp://example.com/a", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)

    def test_file_scheme_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("file:///etc/passwd", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)

    def test_custom_port_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://example.com:8080/", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)

    def test_metadata_port_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://example.com:2375/", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)

    def test_explicit_default_ports_accepted(self):
        for url, port in (
            ("http://example.com/", 80),
            ("http://example.com:80/", 80),
            ("https://example.com/", 443),
            ("https://example.com:443/", 443),
        ):
            with self.subTest(url=url):
                target = validate_target(url, ALLOWED, ok_resolver)
                self.assertEqual(target.port, port)
                self.assertIn(port, ALLOWED_PORTS)

    def test_userinfo_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://user:pass@example.com/", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_URL)


class TestHostAllowlist(unittest.TestCase):
    """规则 2：精确或子域名匹配，IDNA 规范化，去结尾点号。"""

    def test_exact_match(self):
        self.assertTrue(host_allowed("example.com", ALLOWED))

    def test_subdomain_match(self):
        self.assertTrue(host_allowed("feeds.example.com", ALLOWED))
        self.assertTrue(host_allowed("a.b.example.com", ALLOWED))

    def test_suffix_confusion_rejected(self):
        # evil-example.com / example.com.evil.net 均不是子域名
        self.assertFalse(host_allowed("evil-example.com", ALLOWED))
        self.assertFalse(host_allowed("example.com.evil.net", ALLOWED))
        self.assertFalse(host_allowed("notexample.com", ALLOWED))

    def test_trailing_dot_equivalent(self):
        self.assertEqual(normalize_host("example.com."), "example.com")
        self.assertTrue(host_allowed("example.com.", ALLOWED))
        target = validate_target("https://example.com./x", ALLOWED, ok_resolver)
        self.assertEqual(target.host, "example.com")

    def test_idna_normalized(self):
        # 中文域名 → punycode
        self.assertEqual(normalize_host("中国互联网络信息中心.中国").startswith("xn--"), True)
        # 白名单写中文，目标写 punycode，也应命中
        allowed = ("中国.example",)
        punycode = normalize_host("中国.example")
        self.assertTrue(punycode.startswith("xn--"))
        self.assertTrue(host_allowed(punycode, allowed))

    def test_uppercase_normalized(self):
        self.assertEqual(normalize_host("EXAMPLE.COM"), "example.com")
        self.assertTrue(host_allowed("EXAMPLE.COM", ALLOWED))

    def test_host_not_in_allowlist(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://evil.com/", ALLOWED, ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.HOST_NOT_ALLOWED)
        self.assertEqual(ctx.exception.host, "evil.com")


class TestSsrfBlocking(unittest.TestCase):
    """规则 3：所有解析结果都不得落在禁止网段（验收标准 1）。"""

    def test_literal_private_ip_blocked(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://10.0.0.5/", ("10.0.0.5",), ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)
        self.assertIn("10.0.0.5", ctx.exception.resolved_ips)

    def test_literal_metadata_ip_blocked(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://169.254.169.254/latest/meta-data/", ("169.254.169.254",), ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)
        self.assertIn("云元数据", ctx.exception.message)

    def test_stub_dns_to_private_ip_blocked(self):
        """验收标准 1 的核心用例：域名合法，但桩 DNS 解析到 10.0.0.5。"""
        resolver = stub_resolver({"example.com": ["10.0.0.5"]})
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("https://example.com/brief", ALLOWED, resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)
        self.assertEqual(ctx.exception.resolved_ips, ("10.0.0.5",))
        self.assertEqual(ctx.exception.host, "example.com")

    def test_stub_dns_to_metadata_blocked(self):
        resolver = stub_resolver({"feeds.example.com": ["169.254.169.254"]})
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("https://feeds.example.com/rss", ALLOWED, resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)

    def test_one_bad_ip_among_many_blocks_all(self):
        """fail-closed：多 A 记录里只要一个内网，整体拒绝。"""
        resolver = stub_resolver({"example.com": ["93.184.216.34", "192.168.1.10"]})
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("https://example.com/", ALLOWED, resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)
        self.assertEqual(ctx.exception.resolved_ips, ("93.184.216.34", "192.168.1.10"))

    def test_public_ip_allowed(self):
        resolver = stub_resolver({"example.com": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]})
        target = validate_target("https://example.com/", ALLOWED, resolver)
        self.assertEqual(len(target.ips), 2)

    def test_dns_failure_is_network_error(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("https://example.com/", ALLOWED, stub_resolver({}))
        self.assertEqual(ctx.exception.code, ErrorCode.NETWORK_ERROR)

    def test_empty_dns_result_is_network_error(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("https://example.com/", ALLOWED, stub_resolver({"example.com": []}))
        self.assertEqual(ctx.exception.code, ErrorCode.NETWORK_ERROR)


class TestClassifyIp(unittest.TestCase):
    """逐条核对规则 3 列出的网段。"""

    BLOCKED = [
        "127.0.0.1", "127.255.255.254",
        "::1",
        "10.0.0.5", "10.255.255.255",
        "172.16.0.1", "172.31.255.254",
        "192.168.0.1", "192.168.255.255",
        "169.254.0.1", "169.254.169.254",
        "fe80::1", "fe80::abcd:1234",
        "100.64.0.1", "100.127.255.254",
        "0.0.0.0", "0.1.2.3",
        "224.0.0.1", "239.255.255.255",
        "240.0.0.1", "255.255.255.255",
        "192.0.0.1", "192.0.2.1", "198.51.100.7", "203.0.113.9",
        "192.88.99.1", "198.18.0.1",
        "fc00::1", "fd12:3456::1",
        "::ffff:10.0.0.5", "::ffff:192.168.1.1", "::ffff:169.254.169.254", "::ffff:127.0.0.1",
        "fd00:ec2::254",
        "::",
        "ff02::1",
        "64:ff9b::10.0.0.5",
        "2002:0a00:0005::1",
        "2001:db8::1",
        "100::1",
    ]

    ALLOWED = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888"]

    def test_blocked_addresses(self):
        for ip in self.BLOCKED:
            with self.subTest(ip=ip):
                self.assertIsNotNone(classify_ip(ip), f"{ip} 应被判定为禁止")

    def test_allowed_addresses(self):
        for ip in self.ALLOWED:
            with self.subTest(ip=ip):
                self.assertIsNone(classify_ip(ip), f"{ip} 应被判定为可用")

    def test_ipv6_zone_id_rejected(self):
        with self.assertRaises(FetchBlocked) as ctx:
            validate_target("http://[fe80::1%25eth0]/", ("fe80::1%eth0",), ok_resolver)
        self.assertEqual(ctx.exception.code, ErrorCode.SSRF_BLOCKED)


if __name__ == "__main__":
    unittest.main()
