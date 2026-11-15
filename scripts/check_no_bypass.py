#!/usr/bin/env python3
"""静态检查：情报模块内不得存在绕过 safe_fetch 的出站请求。

检查对象是「情报模块目录」（默认 intel/），唯一允许出现 HTTP 客户端的位置是
intel/safe_fetch/ 自身。其余任何模块一旦 import 请求库或调用请求 API，即判违规。

用法
----
    python3 scripts/check_no_bypass.py                # 检查 ./intel
    python3 scripts/check_no_bypass.py intel           # 指定目录
    python3 scripts/check_no_bypass.py . --json        # 输出 JSON（给 CI 用）

退出码：0 = 无违规；1 = 存在违规；2 = 路径错误。
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

#: 允许出现出站 HTTP 客户端代码的白名单目录（相对被检查根目录）
ALLOWED_ZONE = Path("safe_fetch")

#: 禁止导入的第三方/标准库请求客户端
FORBIDDEN_IMPORTS = {
    "requests",
    "httpx",
    "aiohttp",
    "urllib.request",
    "urllib3",
    "http.client",
    "httplib2",
    "pycurl",
    "treq",
    "websocket",
    "websockets",
}

#: 禁止出现的调用形态（属性名，用于抓 urllib.request.urlopen 之类）
FORBIDDEN_CALLS = {
    "urlopen",
    "Request",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "patch",
    "request",
    "Session",
    "AsyncClient",
    "ClientSession",
}

#: 只对「疑似请求对象」生效的调用名，避免把 dict.get 误判
ALWAYS_FORBIDDEN_ATTRS = {"urlopen", "urlretrieve", "urlcleanup"}

REQUEST_RECEIVERS = {"requests", "httpx", "session", "client", "urlopen", "urllib", "aiohttp", "http", "conn"}


@dataclass
class Violation:
    file: str
    line: int
    kind: str
    detail: str


def _imported_modules(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            names.append(node.module)
            for alias in node.names:
                names.append(f"{node.module}.{alias.name}")
        if node.level and node.module is None:
            pass
    return names


def _matches_forbidden(module: str) -> str | None:
    for forbidden in FORBIDDEN_IMPORTS:
        if module == forbidden or module.startswith(forbidden + "."):
            return forbidden
    return None


def _receiver_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    if isinstance(node, ast.Call):
        return _receiver_name(node.func)
    return None


def _scan_file(path: Path, root: Path) -> list[Violation]:
    violations: list[Violation] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        return [Violation(str(path.relative_to(root)), 0, "UNPARSABLE", str(exc))]

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for module in _imported_modules(node):
                hit = _matches_forbidden(module)
                if hit:
                    violations.append(
                        Violation(
                            str(path.relative_to(root)),
                            getattr(node, "lineno", 0),
                            "FORBIDDEN_IMPORT",
                            f"import {module}（{hit}）",
                        )
                    )
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                attr = func.attr
                receiver = _receiver_name(func.value) or ""
                # urlopen 这类名字几乎只属于出站请求，receiver 不做限制
                if attr in ALWAYS_FORBIDDEN_ATTRS:
                    violations.append(
                        Violation(
                            str(path.relative_to(root)),
                            getattr(node, "lineno", 0),
                            "FORBIDDEN_CALL",
                            f"{receiver}.{attr}(...)",
                        )
                    )
                elif attr in FORBIDDEN_CALLS and receiver in REQUEST_RECEIVERS:
                    violations.append(
                        Violation(
                            str(path.relative_to(root)),
                            getattr(node, "lineno", 0),
                            "FORBIDDEN_CALL",
                            f"{receiver}.{attr}(...)",
                        )
                    )
            elif isinstance(func, ast.Name) and func.id in {"urlopen", "urlretrieve"}:
                violations.append(
                    Violation(
                        str(path.relative_to(root)),
                        getattr(node, "lineno", 0),
                        "FORBIDDEN_CALL",
                        f"{func.id}(...)",
                    )
                )
    return violations


def scan(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        # intel/safe_fetch/ 是唯一允许实现出站请求的区域
        if ALLOWED_ZONE.name in rel.parts:
            continue
        violations.extend(_scan_file(path, root))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查情报模块是否绕过 safe_fetch 发请求")
    parser.add_argument("target", nargs="?", default="intel", help="被检查目录（默认 intel）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    parser.add_argument("--quiet", action="store_true", help="无违规时不打印")
    args = parser.parse_args(argv)

    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"[ERROR] 目录不存在：{root}", file=sys.stderr)
        return 2

    violations = scan(root)
    root_label = root.name

    if args.json:
        print(
            json.dumps(
                {
                    "target": str(root),
                    "scanned_python_files": sum(1 for _ in root.rglob("*.py")),
                    "violation_count": len(violations),
                    "violations": [asdict(v) for v in violations],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    elif not violations:
        if not args.quiet:
            print(f"[PASS] {root_label}/ 内未发现绕过 safe_fetch 的出站请求（已跳过 {ALLOWED_ZONE}/ 实现区）")
    else:
        print(f"[FAIL] {root_label}/ 内发现 {len(violations)} 处绕过 safe_fetch 的出站请求：")
        for v in violations:
            print(f"  {v.file}:{v.line}  {v.kind}  {v.detail}")

    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
