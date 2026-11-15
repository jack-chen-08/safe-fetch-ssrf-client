"""safe_fetch —— 情报模块唯一的出站 HTTP 客户端。

外部只应 import 这里的符号：

    from intel.safe_fetch import safe_fetch, Source, SafeFetchConfig, ErrorCode, FetchBlocked
"""

from .client import (
    CONTENT_TYPE_ALLOWLIST,
    REDIRECT_STATUSES,
    SECURITY_LOGGER_NAME,
    FetchResult,
    RawResponse,
    SafeFetchConfig,
    Source,
    safe_fetch,
    socket_transport,
)
from .errors import ErrorCode, FetchBlocked
from .policy import (
    ALLOWED_PORTS,
    ALLOWED_SCHEMES,
    CLOUD_METADATA_ADDRESSES,
    FORBIDDEN_V4,
    FORBIDDEN_V6,
    AllowedTarget,
    classify_ip,
    host_allowed,
    is_ip_literal,
    normalize_host,
    system_resolver,
    validate_target,
)

__version__ = "1.0.0"

__all__ = [
    # 主入口
    "safe_fetch",
    "FetchResult",
    "Source",
    "SafeFetchConfig",
    "RawResponse",
    "socket_transport",
    # 错误
    "ErrorCode",
    "FetchBlocked",
    # 策略（供审计脚本与单测使用）
    "AllowedTarget",
    "validate_target",
    "normalize_host",
    "host_allowed",
    "classify_ip",
    "is_ip_literal",
    "system_resolver",
    "ALLOWED_SCHEMES",
    "ALLOWED_PORTS",
    "FORBIDDEN_V4",
    "FORBIDDEN_V6",
    "CLOUD_METADATA_ADDRESSES",
    "CONTENT_TYPE_ALLOWLIST",
    "REDIRECT_STATUSES",
    "SECURITY_LOGGER_NAME",
    "__version__",
]
