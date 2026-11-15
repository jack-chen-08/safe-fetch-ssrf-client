"""safe_fetch 主流程：IP 固定建连、手动重定向、体积与类型闸门、安全日志。

规则映射
  4) 建连使用已校验 IP，Host 头与 SNI 用原始主机名（防 DNS 重绑定）
  5) 关闭自动重定向，手动跟随最多 3 跳，每跳重新执行完整校验
  6) 连接 5s / 读取 15s / 总时长 30s；原始与解压后体积均 ≤ 10MB
  7) Content-Type 白名单
  8) 不携带 Cookie 与认证头；不读取系统代理环境变量
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit

from .errors import ErrorCode, FetchBlocked
from .policy import AllowedTarget, system_resolver, validate_target

#: 规则 7 的白名单：HTML / XHTML / RSS / Atom / XML / PDF
CONTENT_TYPE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "application/rss+xml",
        "application/atom+xml",
        "application/xml",
        "text/xml",
        "application/pdf",
    }
)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

MEGABYTE = 1024 * 1024

SECURITY_LOGGER_NAME = "intel.safe_fetch.security"
_LOGGER = logging.getLogger(SECURITY_LOGGER_NAME)
# 库代码自带 NullHandler：不污染调用方的 root logger，但调用方配置 handler 后仍能收到安全事件
_LOGGER.addHandler(logging.NullHandler())


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Source:
    """情报来源。``allowed_hosts`` 支持精确主机名与子域名。"""

    name: str
    allowed_hosts: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("Source.allowed_hosts 不能为空")


@dataclass(frozen=True)
class FetchResult:
    """一次成功抓取的结果。"""

    url: str                      # 最终 URL（重定向之后）
    status_code: int
    content_type: str             # 已去掉 charset 等参数
    body: bytes                   # 解压后的正文
    encoding_used: str            # 实际使用的 Content-Encoding，未压缩为 ""
    raw_bytes: int                # 原始（压缩态）字节数
    decoded_bytes: int            # 解压后字节数
    redirects: tuple[str, ...]    # 途经的中间跳
    resolved_ips: tuple[str, ...] # 末跳解析结果
    elapsed_seconds: float

    @property
    def text(self) -> str:
        """按 UTF-8 宽松解码，仅用于调试与日志；生产解析应使用 charset 声明。"""
        return self.body.decode("utf-8", errors="replace")


class RawResponse(Protocol):
    """传输层返回的原始响应，供体积与类型闸门逐块消费。"""

    status: int
    headers: Mapping[str, str]

    def iter_raw(self) -> Iterator[bytes]:  # pragma: no cover - 协议声明
        ...


Transport = Callable[[AllowedTarget, "SafeFetchConfig", float], RawResponse]


@dataclass
class SafeFetchConfig:
    """可注入配置。生产用默认值；测试注入桩解析器与桩传输层。"""

    resolver: Callable[[str, int], Sequence[str]] = system_resolver
    transport: Transport | None = None
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    total_timeout: float = 30.0
    max_redirects: int = 3
    max_body_bytes: int = 10 * MEGABYTE
    max_decoded_bytes: int = 10 * MEGABYTE
    allowed_content_types: frozenset[str] = field(default=CONTENT_TYPE_ALLOWLIST)
    user_agent: str = "intel-briefing-fetcher/1.0 (+safe_fetch)"
    logger: logging.Logger | None = None

    def security_logger(self) -> logging.Logger:
        return self.logger or _LOGGER


# --------------------------------------------------------------------------
# 真实传输层
# --------------------------------------------------------------------------
class _SocketResponse:
    """把 http.client.HTTPResponse 包成 RawResponse，保持底层 socket 句柄可控。"""

    def __init__(self, response: http.client.HTTPResponse, sock: socket.socket) -> None:
        self._response = response
        self._sock = sock
        self.status = response.status
        self.headers = {k.lower(): v for k, v in response.getheaders()}

    def iter_raw(self) -> Iterator[bytes]:
        try:
            while True:
                chunk = self._response.read(64 * 1024)
                if not chunk:
                    return
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            try:
                self._sock.close()
            except OSError:
                pass


def _build_request(target: AllowedTarget, cfg: SafeFetchConfig) -> bytes:
    """手写请求行与头部：Host 用域名、不带 Cookie/Authorization。"""
    lines = [
        f"GET {target.request_target} HTTP/1.1",
        f"Host: {target.host_header}",
        f"User-Agent: {cfg.user_agent}",
        "Accept: text/html,application/xhtml+xml,application/xml,application/pdf;q=0.9,*/*;q=0.1",
        "Accept-Encoding: gzip, deflate",
        "Connection: close",
    ]
    # 规则 8：不携带 Cookie / Authorization / Proxy-Authorization，此处刻意不提供扩展点
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def socket_transport(target: AllowedTarget, cfg: SafeFetchConfig, remaining: float) -> RawResponse:
    """默认传输层：用已校验 IP 建连，TLS 用原始主机名做 SNI 与证书校验（规则 4）。"""
    if remaining <= 0:
        raise FetchBlocked(ErrorCode.TIMEOUT, "总时长已用尽，未发起连接", url=target.url, host=target.host)

    connect_timeout = max(0.1, min(cfg.connect_timeout, remaining))
    connect_deadline = time.monotonic() + connect_timeout
    last_error: Exception | None = None
    last_was_timeout = False
    sock: socket.socket | None = None
    # 所有 IP 都已通过规则 3 校验，逐个尝试属于可用范围内的容错：
    # 单个 IP 连接超时不应直接放弃 —— 目标可能只是该边缘节点不可达。
    # 整个连接阶段共享 connect_timeout 预算，避免 IP 多时无限拖长。
    for ip in target.ips:
        budget = connect_deadline - time.monotonic()
        if budget <= 0:
            break
        try:
            sock = socket.create_connection((ip, target.port), timeout=budget)
            break
        except OSError as exc:  # 连接超时 / 被拒 / 网络不可达
            last_error = exc
            last_was_timeout = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()
            continue

    if sock is None:
        if last_was_timeout:
            raise FetchBlocked(
                ErrorCode.TIMEOUT,
                f"连接 {target.host}:{target.port} 超时（>{connect_timeout:.1f}s，已试 {len(target.ips)} 个 IP）",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            ) from last_error
        raise FetchBlocked(
            ErrorCode.NETWORK_ERROR,
            f"无法连接 {target.host}:{target.port}（{last_error}）",
            url=target.url,
            host=target.host,
            resolved_ips=target.ips,
        ) from last_error

    try:
        if target.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target.host)

        read_timeout = max(0.1, min(cfg.read_timeout, remaining))
        sock.settimeout(read_timeout)
        sock.sendall(_build_request(target, cfg))
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        return _SocketResponse(response, sock)
    except FetchBlocked:
        sock.close()
        raise
    except (TimeoutError, socket.timeout) as exc:
        sock.close()
        raise FetchBlocked(
            ErrorCode.TIMEOUT,
            f"读取响应超时（>{cfg.read_timeout:.0f}s）",
            url=target.url,
            host=target.host,
            resolved_ips=target.ips,
        ) from exc
    except (ssl.SSLError, http.client.HTTPException, OSError) as exc:
        sock.close()
        raise FetchBlocked(
            ErrorCode.NETWORK_ERROR,
            f"传输失败：{type(exc).__name__}: {exc}",
            url=target.url,
            host=target.host,
            resolved_ips=target.ips,
        ) from exc


# --------------------------------------------------------------------------
# 安全日志（规则：被拦截的请求记录 URL、解析 IP、原因）
# --------------------------------------------------------------------------
def _log_block(cfg: SafeFetchConfig, source_name: str, exc: FetchBlocked) -> None:
    logger = cfg.security_logger()
    logger.warning(
        "safe_fetch.blocked code=%s source=%s url=%s host=%s ips=%s reason=%s",
        exc.code.value,
        source_name,
        exc.url or "-",
        exc.host or "-",
        ",".join(exc.resolved_ips) or "-",
        exc.message,
        extra={
            "event": "safe_fetch.blocked",
            "code": exc.code.value,
            "source": source_name,
            "url": exc.url,
            "host": exc.host,
            "resolved_ips": list(exc.resolved_ips),
            "reason": exc.message,
        },
    )


# --------------------------------------------------------------------------
# 体积与解压（规则 6）
# --------------------------------------------------------------------------
def _content_encoding(headers: Mapping[str, str]) -> str:
    return (headers.get("content-encoding") or "").strip().lower()


def _read_limited(
    response: RawResponse,
    cfg: SafeFetchConfig,
    target: AllowedTarget,
    deadline: float,
) -> tuple[bytes, int, str]:
    """流式读取并按原始体积、解压后体积双闸限制。"""
    encoding = _content_encoding(response.headers)
    decompressor: Any = None
    if "gzip" in encoding:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif "deflate" in encoding:
        decompressor = zlib.decompressobj()

    raw_total = 0
    decoded_total = 0
    decoded = bytearray()

    for chunk in response.iter_raw():
        if time.monotonic() > deadline:
            raise FetchBlocked(
                ErrorCode.TIMEOUT,
                f"读取正文超过总时长 {cfg.total_timeout:.0f}s",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            )
        raw_total += len(chunk)
        if raw_total > cfg.max_body_bytes:
            raise FetchBlocked(
                ErrorCode.TOO_LARGE,
                f"响应体超过 {cfg.max_body_bytes} 字节上限（已读 {raw_total}）",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            )
        if decompressor is None:
            decoded.extend(chunk)
        else:
            try:
                out = decompressor.decompress(chunk)
            except zlib.error as exc:
                raise FetchBlocked(
                    ErrorCode.NETWORK_ERROR,
                    f"响应解压失败（{encoding}）：{exc}",
                    url=target.url,
                    host=target.host,
                    resolved_ips=target.ips,
                ) from exc
            decoded.extend(out)
        decoded_total = len(decoded)
        # 解压后体积是压缩炸弹的主闸门，必须在累积过程中就中断，不能读完再判
        if decoded_total > cfg.max_decoded_bytes:
            raise FetchBlocked(
                ErrorCode.TOO_LARGE,
                f"解压后体积超过 {cfg.max_decoded_bytes} 字节上限（已解出 {decoded_total}）",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            )

    if decompressor is not None:
        try:
            tail = decompressor.flush()
        except zlib.error as exc:
            raise FetchBlocked(
                ErrorCode.NETWORK_ERROR,
                f"响应解压收尾失败（{encoding}）：{exc}",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            ) from exc
        decoded.extend(tail)
        if len(decoded) > cfg.max_decoded_bytes:
            raise FetchBlocked(
                ErrorCode.TOO_LARGE,
                f"解压后体积超过 {cfg.max_decoded_bytes} 字节上限",
                url=target.url,
                host=target.host,
                resolved_ips=target.ips,
            )

    return bytes(decoded), raw_total, encoding


def _mime(content_type: str) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


# --------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------
def safe_fetch(
    url: str,
    source: Source | Mapping[str, Any],
    config: SafeFetchConfig | None = None,
) -> FetchResult:
    """抓取情报源内容。情报模块所有出站请求都必须经过此函数。

    参数
    ----
    url: 目标 URL（http/https，端口 80/443）。
    source: 来源定义，含 ``allowed_hosts``；也接受 ``{"name":..,"allowed_hosts":[...]}``。
    config: 可选配置，测试时注入桩解析器 / 桩传输层。

    异常
    ----
    FetchBlocked: 携带 ErrorCode，且拦截事件已写入安全日志。
    """
    cfg = config or SafeFetchConfig()
    source_name, allowed_hosts = _unpack_source(source)
    transport = cfg.transport or socket_transport

    started = time.monotonic()
    deadline = started + cfg.total_timeout

    current_url = url
    redirects: list[str] = []

    for hop in range(cfg.max_redirects + 1):
        try:
            target = validate_target(current_url, allowed_hosts, cfg.resolver)
        except FetchBlocked as exc:
            _log_block(cfg, source_name, exc)
            raise

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exc = FetchBlocked(
                ErrorCode.TIMEOUT,
                f"总时长 {cfg.total_timeout:.0f}s 用尽（第 {hop + 1} 跳）",
                url=current_url,
                host=target.host,
                resolved_ips=target.ips,
            )
            _log_block(cfg, source_name, exc)
            raise exc

        try:
            response = transport(target, cfg, remaining)
        except FetchBlocked as exc:
            _log_block(cfg, source_name, exc)
            raise

        location = response.headers.get("location")

        if response.status in REDIRECT_STATUSES and location:
            _drain(response)
            if hop >= cfg.max_redirects:
                exc = FetchBlocked(
                    ErrorCode.TOO_MANY_REDIRECTS,
                    f"重定向超过 {cfg.max_redirects} 跳",
                    url=current_url,
                    host=target.host,
                    resolved_ips=target.ips,
                )
                _log_block(cfg, source_name, exc)
                raise exc
            next_url = urljoin(current_url, location)
            redirects.append(next_url)
            current_url = next_url
            # 下一跳回到循环顶部，重新执行 scheme/端口/白名单/DNS/IP 全量校验
            continue

        content_type_raw = response.headers.get("content-type", "")
        content_type = _mime(content_type_raw)
        if content_type not in cfg.allowed_content_types:
            _drain(response)
            exc = FetchBlocked(
                ErrorCode.BAD_CONTENT_TYPE,
                f"Content-Type 不在白名单内：{content_type or '(缺失)'}",
                url=current_url,
                host=target.host,
                resolved_ips=target.ips,
                detail={"content_type": content_type_raw},
            )
            _log_block(cfg, source_name, exc)
            raise exc

        try:
            body, raw_bytes, encoding = _read_limited(response, cfg, target, deadline)
        except FetchBlocked as exc:
            _log_block(cfg, source_name, exc)
            raise

        return FetchResult(
            url=current_url,
            status_code=response.status,
            content_type=content_type,
            body=body,
            encoding_used=encoding,
            raw_bytes=raw_bytes,
            decoded_bytes=len(body),
            redirects=tuple(redirects),
            resolved_ips=target.ips,
            elapsed_seconds=time.monotonic() - started,
        )

    # 循环理论上不会走到这里（超跳数在循环内已抛）
    raise FetchBlocked(  # pragma: no cover
        ErrorCode.TOO_MANY_REDIRECTS,
        f"重定向超过 {cfg.max_redirects} 跳",
        url=current_url,
    )


def _unpack_source(source: Source | Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    if isinstance(source, Source):
        return source.name, source.allowed_hosts
    if isinstance(source, Mapping):
        hosts = source.get("allowed_hosts") or ()
        if not hosts:
            raise ValueError("source.allowed_hosts 不能为空")
        return str(source.get("name") or "unnamed"), tuple(hosts)
    hosts = getattr(source, "allowed_hosts", None)
    if not hosts:
        raise ValueError("source 必须提供 allowed_hosts")
    return str(getattr(source, "name", "unnamed")), tuple(hosts)


def _drain(response: RawResponse) -> None:
    """把剩余响应体读掉再关闭，避免连接悬挂；不累计、不判体积。"""
    try:
        for _ in response.iter_raw():
            pass
    except Exception:  # noqa: BLE001 - 排空失败不影响主流程
        pass


__all__ = [
    "CONTENT_TYPE_ALLOWLIST",
    "REDIRECT_STATUSES",
    "Source",
    "FetchResult",
    "SafeFetchConfig",
    "RawResponse",
    "socket_transport",
    "safe_fetch",
    "SECURITY_LOGGER_NAME",
]
