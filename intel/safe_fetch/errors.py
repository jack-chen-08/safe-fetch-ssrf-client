"""safe_fetch 的错误码定义。

规则里指定的六个错误码是本模块的对外契约；额外两个（BAD_URL / NETWORK_ERROR）
用于把「非法入参」和「网络层失败」与 SSRF 判定区分开，避免安全语义被稀释。
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """对外错误码。值即序列化后的字符串。"""

    # --- 规则指定的六个 ---
    SSRF_BLOCKED = "SSRF_BLOCKED"
    """主机解析结果落在禁止网段（回环/私网/link-local/保留/元数据）。"""

    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    """主机不在来源 allowed_hosts 内，或 scheme/端口未被允许。"""

    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    """重定向跳数超过 3。"""

    TOO_LARGE = "TOO_LARGE"
    """原始响应体或解压后体积超过 10MB。"""

    TIMEOUT = "TIMEOUT"
    """连接/读取/总时长超时。"""

    BAD_CONTENT_TYPE = "BAD_CONTENT_TYPE"
    """Content-Type 不在 HTML/XHTML/RSS/Atom/XML/PDF 白名单内。"""

    # --- 扩展：不与上述语义混淆 ---
    BAD_URL = "BAD_URL"
    """URL 无法解析、缺主机、含用户信息或非 http(s) scheme。"""

    NETWORK_ERROR = "NETWORK_ERROR"
    """DNS 失败、连接被拒、TLS 握手失败、连接中途断开等网络层错误。"""


class FetchBlocked(Exception):
    """safe_fetch 统一抛出的失败类型。

    ``code``    : ErrorCode
    ``url``     : 触发失败的 URL（重定向后为当前跳的 URL）
    ``host``    : 该 URL 的主机（已规范化）
    ``resolved_ips`` : 本次解析得到的全部 IP（DNS 失败时为空）
    ``reason``  : 人类可读原因，同时写入安全日志
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        url: str = "",
        host: str = "",
        resolved_ips: tuple[str, ...] = (),
        detail: Any = None,
    ) -> None:
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message
        self.url = url
        self.host = host
        self.resolved_ips = tuple(resolved_ips)
        self.detail = detail

    @property
    def reason(self) -> str:
        """``message`` 的别名：对外文档与日志里统一叫 reason。"""
        return self.message

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "url": self.url,
            "host": self.host,
            "resolved_ips": list(self.resolved_ips),
            "detail": self.detail,
        }

    def __str__(self) -> str:  # pragma: no cover - 便于日志
        return f"[{self.code.value}] {self.message} (url={self.url!r}, ips={list(self.resolved_ips)})"


__all__ = ["ErrorCode", "FetchBlocked"]
