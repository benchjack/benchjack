"""
Shared path constants for the BenchJack server.
"""
from pathlib import Path

_SERVER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = _SERVER_DIR.parent
WEB_DIR = PROJECT_ROOT / "web"
TOOLS_DIR = PROJECT_ROOT / ".claude" / "skills" / "benchjack" / "tools"
