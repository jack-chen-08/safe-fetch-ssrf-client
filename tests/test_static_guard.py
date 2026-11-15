"""验收标准 4：静态检查脚本必须能确认情报模块内无绕过 safe_fetch 的出站请求。

双向自证：
  * 对本项目 intel/ 扫描 → 0 违规（合规）
  * 对 tests/fixtures/ 扫描 → 抓到全部 4 处违规（闸门有效）
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_no_bypass.py"


def run_scan(target: str, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), target, *extra],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestStaticGuard(unittest.TestCase):
    def test_project_intel_is_clean(self):
        proc = run_scan("intel")
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("[PASS]", proc.stdout)

    def test_guard_catches_bypass_fixture(self):
        proc = run_scan("tests/fixtures")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("[FAIL]", proc.stdout)
        for expected in ("forbidden_import", "forbidden_call"):
            self.assertIn(expected.upper(), proc.stdout.upper())
        # 4 处违规：urllib.request、requests、requests.get、urlopen
        self.assertIn("4 处", proc.stdout)

    def test_json_output_is_machine_readable(self):
        proc = run_scan("tests/fixtures", "--json")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["violation_count"], 4)
        kinds = {v["kind"] for v in payload["violations"]}
        self.assertEqual(kinds, {"FORBIDDEN_IMPORT", "FORBIDDEN_CALL"})
        self.assertTrue(all(v["file"].endswith("bypass_sample.py") for v in payload["violations"]))

    def test_missing_directory_exit_code(self):
        proc = run_scan("no_such_dir_xyz")
        self.assertEqual(proc.returncode, 2)

    def test_safe_fetch_zone_is_skipped(self):
        """实现区（intel/safe_fetch）允许使用标准库 http.client，不应被误报。"""
        proc = run_scan(".", "--json")
        payload = json.loads(proc.stdout)
        offenders = {v["file"] for v in payload["violations"]}
        self.assertFalse([f for f in offenders if f.startswith("intel/safe_fetch")])


if __name__ == "__main__":
    unittest.main()
