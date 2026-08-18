"""Verify demo.py runs without errors."""

import os
import subprocess
import sys


def test_demo_runs_successfully():
    """demo.py should execute all 12 sections without assertion errors."""
    from pathlib import Path
    repo_root = Path(__file__).resolve().parent.parent
    demo_path = repo_root / "scripts" / "demo.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, str(demo_path)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(repo_root),
        env=env,
    )
    assert result.returncode == 0, f"demo.py failed:\n{result.stderr}"
    assert "ALL SECTIONS PASSED" in result.stdout
