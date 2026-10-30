"""Convenience entry point for `python remediation_executor.py`."""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.executor import run_executor


if __name__ == "__main__":
    run_executor()
