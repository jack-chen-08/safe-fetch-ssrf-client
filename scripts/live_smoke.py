#!/usr/bin/env python3
"""真实网络冒烟测试（不属于 CI 套件：需要出网）。

单元测试全部用桩传输层，覆盖的是策略与闸门逻辑；这个脚本负责证明「真实 socket 路径
（IP 固定建连 + SNI + 证书校验）确实能取回内容」，并把四个拦截场景在真实环境里跑一遍。

    python3 scripts/live_smoke.py [--host example.com]

退出码 0 表示预期全部命中。
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from intel.safe_fetch import ErrorCode, FetchBlocked, Source, safe_fetch  # noqa: E402


def expect_block(url: str, source: Source, code: ErrorCode) -> bool:
    started = time.monotonic()
    try:
        result = safe_fetch(url, source)
    except FetchBlocked as exc:
        ok = exc.code is code
        print(f"  [{'OK ' if ok else 'BAD'}] {url}\n        -> {exc.code.value}: {exc.reason}  ({time.monotonic() - started:.2f}s)")
        return ok
    print(f"  [BAD] {url} 未被拦截，返回 {result.status_code}")
    return False


def expect_ok(url: str, source: Source) -> bool:
    started = time.monotonic()
    try:
        result = safe_fetch(url, source)
    except FetchBlocked as exc:
        print(f"  [BAD] {url}\n        -> 被拦截：{exc.code.value}: {exc.reason}")
        return False
    print(
        f"  [OK ] {url}\n        -> {result.status_code} {result.content_type} "
        f"{len(result.body)}B ips={result.resolved_ips} ({time.monotonic() - started:.2f}s)"
    )
    return 200 <= result.status_code < 300 and len(result.body) > 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="example.com", help="用于正向抓取的公网域名")
    args = parser.parse_args()

    source = Source(name="live-smoke", allowed_hosts=(args.host,))
    results: list[bool] = []

    print("1) 正向：真实 HTTPS 抓取（IP 直连 + SNI）")
    results.append(expect_ok(f"https://{args.host}/", source))

    print("2) 正向：真实 HTTP 抓取")
    results.append(expect_ok(f"http://{args.host}/", source))

    print("3) 拦截：主机不在白名单")
    results.append(expect_block("https://example.org/", source, ErrorCode.HOST_NOT_ALLOWED))

    print("4) 拦截：端口非法")
    results.append(expect_block(f"https://{args.host}:8443/", source, ErrorCode.HOST_NOT_ALLOWED))

    print("5) 拦截：云元数据地址（IP 字面量）")
    meta = Source(name="live-smoke-meta", allowed_hosts=("169.254.169.254",))
    results.append(expect_block("http://169.254.169.254/latest/meta-data/", meta, ErrorCode.SSRF_BLOCKED))

    print("6) 拦截：私网地址（IP 字面量）")
    private = Source(name="live-smoke-private", allowed_hosts=("10.0.0.5",))
    results.append(expect_block("http://10.0.0.5/admin", private, ErrorCode.SSRF_BLOCKED))

    passed = sum(results)
    print(f"\n{passed}/{len(results)} 项符合预期")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
