from __future__ import annotations

import subprocess
import sys
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
RULE = """title: Cmd Test Rule
id: 77777777-7777-7777-7777-777777777777
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sigmatch", *args],
        cwd=TOOL_ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=120,
    )


def test_cli_validate(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(RULE, encoding="utf-8")
    proc = run_cli("validate", "--rules", str(rules), "--quiet")
    assert proc.returncode == 0, proc.stderr
    assert "Validation OK" in proc.stdout
    assert "Rules loaded: 1" in proc.stdout


def test_cli_validate_reports_rule_errors(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text(
        """title: Bad
id: 88888888-8888-8888-8888-888888888888
status: test
level: low
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: cmd.exe
  condition: selection and no_such_selection
""",
        encoding="utf-8",
    )
    proc = run_cli("validate", "--rules", str(rules), "--quiet")
    assert proc.returncode == 1
    assert "unknown selection" in proc.stdout
