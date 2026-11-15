#!/usr/bin/env bash
# 一键验证：单元测试 + 绕过检查（离线，无需出网）
set -euo pipefail
cd "$(dirname "$0")"
echo "== 单元测试（离线，桩 DNS + 桩传输）=="
python3 -m unittest discover -s tests -t . -v
echo
echo "== 静态检查：情报模块内无绕过 safe_fetch 的出站请求 =="
python3 scripts/check_no_bypass.py
