# tests/conftest.py — pytest configuration and shared fixtures
import sys
import pathlib
import pytest
from unittest.mock import patch, MagicMock

# Add project root to path
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def mock_shell():
    """Fixture: mock all shell execution so tests run without root or tools."""
    with patch("utils.shell.run_cmd",     return_value=(0, "")), \
         patch("utils.shell.cmd_exists",  return_value=False), \
         patch("utils.shell.read_file",   return_value=None), \
         patch("utils.shell.is_readable", return_value=False), \
         patch("utils.shell.is_writable", return_value=False), \
         patch("utils.shell.file_exists", return_value=False), \
         patch("utils.shell.dir_exists",  return_value=False):
        yield


@pytest.fixture
def mock_network():
    """Fixture: mock all network calls."""
    import socket
    with patch("socket.socket"), \
         patch("socket.gethostbyname", side_effect=Exception("mocked")), \
         patch("socket.gethostbyaddr", side_effect=Exception("mocked")), \
         patch("socket.gethostbyname_ex", side_effect=Exception("mocked")):
        yield


@pytest.fixture
def sample_args():
    """Fixture: mock argparse Namespace for plugins."""
    args = MagicMock()
    args.target   = "127.0.0.1"
    args.domain   = ""
    args.port     = 80
    args.verbose  = False
    args.all_checks = True
    return args


@pytest.fixture
def sample_session():
    """Fixture: a realistic PhantomX session dict for testing."""
    return {
        "start_time": "2024-06-01T10:00:00",
        "hostname":   "test-target",
        "user":       "tester",
        "results": {
            "privesc": {
                "suid_interesting": ["/usr/bin/python3"],
                "sudo_findings":    [["NOPASSWD ALL", "critical", "Full access"]],
                "dangerous_groups": ["docker"],
                "kernel_version":   "5.15.0",
            },
            "loot": {
                "shadow": {"readable": False},
                "ssh_keys": [],
                "cloud_creds": [],
            },
            "audit": {
                "ssh_hardening": [["PermitRootLogin", "yes", "critical", "root login"]],
                "password_policy": [],
            },
        }
    }
