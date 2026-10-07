"""
utils/shell.py — Safe shell command execution helpers
"""

import subprocess
import shutil
import os
from typing import Optional, Tuple


def run_cmd(
    cmd: str,
    timeout: int = 15,
    shell: bool = True,
    capture_stderr: bool = False
) -> Tuple[int, str]:
    """
    Execute a shell command safely.

    Returns:
        (returncode, stdout_output)
    """
    stderr_pipe = subprocess.PIPE if capture_stderr else subprocess.DEVNULL
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=stderr_pipe,
            timeout=timeout,
            text=True,
            env={**os.environ, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        )
        return proc.returncode, proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return -1, "[TIMEOUT]"
    except FileNotFoundError:
        return -1, "[NOT FOUND]"
    except Exception as exc:
        return -1, f"[ERROR: {exc}]"


def cmd_exists(binary: str) -> bool:
    """Check if a binary is on PATH."""
    return shutil.which(binary) is not None


def read_file(path: str) -> Optional[str]:
    """
    Safely read a file, returning None on failure.
    """
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except PermissionError:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def file_exists(path: str) -> bool:
    return os.path.isfile(path)


def dir_exists(path: str) -> bool:
    return os.path.isdir(path)


def is_readable(path: str) -> bool:
    return os.access(path, os.R_OK)


def is_writable(path: str) -> bool:
    return os.access(path, os.W_OK)


def get_current_user() -> str:
    _, out = run_cmd("whoami")
    return out or os.getenv("USER", "unknown")


def get_uid() -> int:
    return os.getuid()


def is_root() -> bool:
    return os.getuid() == 0
