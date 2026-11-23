"""Tests always use an isolated temporary database and offline providers."""
import os
import tempfile
from pathlib import Path

TEST_DIRECTORY = Path(tempfile.mkdtemp(prefix="multi-agent-security-tests-"))
os.environ["DATABASE_URL"] = "sqlite:///" + (TEST_DIRECTORY / "test.db").as_posix()
os.environ["AGENT_MODE"] = "offline"
os.environ["WORKER_ENABLED"] = "false"
