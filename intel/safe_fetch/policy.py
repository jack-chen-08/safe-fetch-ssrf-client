"""URL / 主机 / IP 的策略校验层（规则 1、2、3）。

这一层只做判断，不发请求，因此可以完全离线单测。
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .errors import ErrorCode, FetchBlocked

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = {80, 443}
DEFAULT_PORTS = {"http": 80, "https": 443}

#: 规则 3 的禁止网段，逐条列出并附原因，便于安全日志直接引用
FORBIDDEN_V4: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "本网络 (0.0.0.0/8)"),
    ("10.0.0.0/8", "私网 A (10.0.0.0/8)"),
    ("100.64.0.0/10", "运营商级 NAT (100.64.0.0/10)"),
    ("127.0.0.0/8", "回环 (127.0.0.0/8)"),
    ("169.254.0.0/16", "link-local (169.254.0.0/16)"),
    ("172.16.0.0/12", "私网 B (172.16.0.0/12)"),
    ("192.0.0.0/24", "IETF 协议分配 (192.0.0.0/24)"),
    ("192.0.2.0/24", "文档 TEST-NET-1 (192.0.2.0/24)"),
    ("192.88.99.0/24", "6to4 中继 (192.88.99.0/24)"),
    ("192.168.0.0/16", "私网 C (192.168.0.0/16)"),
    ("198.18.0.0/15", "基准测试 (198.18.0.0/15)"),
    ("198.51.100.0/24", "文档 TEST-NET-2 (198.51.100.0/24)"),
    ("203.0.113.0/24", "文档 TEST-NET-3 (203.0.113.0/24)"),
    ("224.0.0.0/4", "组播 (224.0.0.0/4)"),
    ("240.0.0.0/4", "保留 (240.0.0.0/4)"),
)

FORBIDDEN_V6: tuple[tuple[str, str], ...] = (
    ("::/128", "未指定地址 (::)"),
    ("::1/128", "回环 (::1)"),
    ("64:ff9b::/96", "NAT64 (64:ff9b::/96)"),
    ("100::/64", "丢弃前缀 (100::/64)"),
    ("2001:db8::/32", "文档 (2001:db8::/32)"),
    ("2002::/16", "6to4 (2002::/16)"),
    ("fc00::/7", "唯一本地地址 (fc00::/7)"),
    ("fe80::/10", "link-local (fe80::/10)"),
    ("ff00::/8", "组播 (ff00::/8)"),
)

#: 云元数据端点单列，命中时日志原因更精准（已被上面网段覆盖，此处仅为可读性）
CLOUD_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})

_V4_NETS = tuple((ipaddress.ip_network(cidr), why) for cidr, why in FORBIDDEN_V4)
_V6_NETS = tuple((ipaddress.ip_network(cidr), why) for cidr, why in FORBIDDEN_V6)
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


class Resolver(Protocol):
    """DNS 解析器协议：返回该主机的全部 IP 字符串。"""

    def __call__(self, host: str, port: int) -> Sequence[str]:  # pragma: no cover
        ...


def system_resolver(host: str, port: int) -> list[str]:
    """默认解析器：一次查询拿到全部 A/AAAA 结果（AF_UNSPEC）。"""
    infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return seen


# --------------------------------------------------------------------------
# 主机名规范化与白名单匹配（规则 2）
# --------------------------------------------------------------------------
def normalize_host(raw: str) -> str:
    """IDNA 规范化 + 小写 + 去掉结尾点号。

    - 中文/全角域名 → punycode（IDNA）
    - 去尾点（``example.com.`` 与 ``example.com`` 等价）
    - 纯 IP 字面量原样返回其规范文本形式
    """
    host = (raw or "").strip()
    if not host:
        raise FetchBlocked(ErrorCode.BAD_URL, "URL 缺少主机名", url=raw)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        raise FetchBlocked(ErrorCode.SSRF_BLOCKED, f"主机名含 IPv6 zone id，已拒绝：{host}", host=host)

    host = host.rstrip(".")
    if not host:
        raise FetchBlocked(ErrorCode.BAD_URL, "主机名为空（仅含点号）")

    literal = _try_ip(host)
    if literal is not None:
        return literal

    lowered = host.lower()
    try:
        # 已是 ASCII 时 idna 编码是幂等的；非 ASCII 时转 punycode
        return lowered.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise FetchBlocked(ErrorCode.BAD_URL, f"主机名无法做 IDNA 规范化：{host}（{exc}）", host=host) from exc


def _try_ip(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def is_ip_literal(host: str) -> bool:
    return _try_ip(host) is not None


def host_allowed(host: str, allowed_hosts: Iterable[str]) -> bool:
    """精确匹配或子域匹配。``allowed_hosts`` 里的条目同样先做规范化。"""
    target = normalize_host(host)
    for entry in allowed_hosts:
        candidate = normalize_host(entry)
        # 允许条目写成 ".example.com" 的旧式通配前缀
        if candidate.startswith("."):
            candidate = candidate[1:]
        if target == candidate or target.endswith("." + candidate):
            return True
    return False


# --------------------------------------------------------------------------
# IP 判定（规则 3）
# --------------------------------------------------------------------------
def classify_ip(raw_ip: str) -> str | None:
    """返回禁止原因；``None`` 表示该 IP 可用。"""
    try:
        address = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return f"无法解析为 IP：{raw_ip!r}"
    if str(address) in CLOUD_METADATA_ADDRESSES:
        return f"云元数据端点 ({address})"

    # IPv4-mapped IPv6（::ffff:10.0.0.5）先拆出 IPv4 再按 IPv4 网段判
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        inner = address.ipv4_mapped
        inner_reason = _classify_v4(inner)
        if inner_reason:
            return f"IPv4 映射的 IPv6 地址 {address} → {inner_reason}"
        return None

    if isinstance(address, ipaddress.IPv4Address):
        return _classify_v4(address)
    return _classify_v6(address)


def _classify_v4(address: ipaddress.IPv4Address) -> str | None:
    for network, why in _V4_NETS:
        if address in network:
            return why
    if address.is_loopback or address.is_private or address.is_reserved or address.is_multicast:
        return f"私有/保留/组播地址 ({address})"
    if address.is_link_local:
        return f"link-local ({address})"
    if address.is_unspecified:
        return f"未指定地址 ({address})"
    return None


def _classify_v6(address: ipaddress.IPv6Address) -> str | None:
    for network, why in _V6_NETS:
        if address in network:
            return why
    if (
        address.is_loopback
        or address.is_private
        or address.is_reserved
        or address.is_multicast
        or address.is_link_local
        or address.is_unspecified
    ):
        return f"私有/保留/组播/link-local 地址 ({address})"
    return None


# --------------------------------------------------------------------------
# 单个 URL 的完整校验（规则 1 + 2 + 3）
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class AllowedTarget:
    """通过全部静态与 DNS 校验的目标，可直接用于建连。"""

    url: str
    scheme: str
    host: str
    port: int
    host_header: str
    request_target: str
    ips: tuple[str, ...]
    host_is_literal: bool


def validate_target(
    url: str,
    allowed_hosts: Iterable[str],
    resolver: Callable[[str, int], Sequence[str]] = system_resolver,
) -> AllowedTarget:
    """校验 scheme / 端口 / 主机白名单 / DNS 解析结果，返回可建连目标。"""
    if not isinstance(url, str) or not url.strip():
        raise FetchBlocked(ErrorCode.BAD_URL, "URL 为空")
    parts = urlsplit(url.strip())

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise FetchBlocked(
            ErrorCode.HOST_NOT_ALLOWED,
            f"只允许 http/https，收到 scheme={scheme or '(缺失)'}",
            url=url,
        )
    if "@" in parts.netloc:
        raise FetchBlocked(ErrorCode.BAD_URL, "URL 含用户信息（user:pass@），已拒绝", url=url)
    if not parts.hostname:
        raise FetchBlocked(ErrorCode.BAD_URL, "URL 缺少主机名", url=url)

    try:
        port = parts.port
    except ValueError as exc:
        raise FetchBlocked(ErrorCode.BAD_URL, f"端口非法：{exc}", url=url) from exc
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise FetchBlocked(
            ErrorCode.HOST_NOT_ALLOWED,
            f"只允许 80/443 端口，收到 {port}",
            url=url,
        )

    host = normalize_host(parts.hostname)
    if not host_allowed(host, allowed_hosts):
        raise FetchBlocked(
            ErrorCode.HOST_NOT_ALLOWED,
            f"主机 {host} 不在来源白名单内",
            url=url,
            host=host,
        )

    host_is_literal = is_ip_literal(host)
    if host_is_literal:
        ips = (host,)
    else:
        try:
            ips = tuple(dict.fromkeys(resolver(host, port)))
        except (socket.gaierror, OSError, UnicodeError) as exc:
            raise FetchBlocked(
                ErrorCode.NETWORK_ERROR,
                f"DNS 解析失败：{host}（{exc}）",
                url=url,
                host=host,
            ) from exc
        if not ips:
            raise FetchBlocked(ErrorCode.NETWORK_ERROR, f"DNS 未返回任何地址：{host}", url=url, host=host)

    # 规则 3 的关键语义：**全部**解析结果都必须合规，任一命中禁止网段即整体拒绝（fail-closed）
    for ip in ips:
        reason = classify_ip(ip)
        if reason is not None:
            raise FetchBlocked(
                ErrorCode.SSRF_BLOCKED,
                f"主机 {host} 解析到被禁止的地址 {ip}：{reason}",
                url=url,
                host=host,
                resolved_ips=ips,
            )

    host_header = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        host_header = f"[{host}]" if port == DEFAULT_PORTS[scheme] else f"[{host}]:{port}"

    request_target = parts.path or "/"
    if parts.query:
        request_target = f"{request_target}?{parts.query}"

    return AllowedTarget(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        host_header=host_header,
        request_target=request_target,
        ips=ips,
        host_is_literal=host_is_literal,
    )


__all__ = [
    "ALLOWED_SCHEMES",
    "ALLOWED_PORTS",
    "DEFAULT_PORTS",
    "FORBIDDEN_V4",
    "FORBIDDEN_V6",
    "CLOUD_METADATA_ADDRESSES",
    "AllowedTarget",
    "normalize_host",
    "is_ip_literal",
    "host_allowed",
    "classify_ip",
    "system_resolver",
    "validate_target",
]
