#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
import os


DEFAULT_HOSTEXEC_TIMEOUT_MS = 30000
DEFAULT_REMOTE_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def resolve_remote_python() -> str:
    return os.getenv("X64DBG_REMOTE_PYTHON", "")


def resolve_remote_powershell(default: str = DEFAULT_REMOTE_POWERSHELL) -> str:
    return os.getenv("X64DBG_REMOTE_POWERSHELL", default)


def resolve_hostexec_cwd() -> str:
    return os.getenv("X64DBG_HOSTEXEC_CWD", "")


def resolve_hostexec_timeout_ms(default: int = DEFAULT_HOSTEXEC_TIMEOUT_MS) -> int:
    raw = os.getenv("X64DBG_HOSTEXEC_TIMEOUT_MS", "").strip()
    if not raw:
        return default
    try:
        value = int(raw, 0)
    except ValueError:
        return default
    return value if value > 0 else default


def add_hostexec_common_arguments(
    parser: ArgumentParser,
    *,
    include_cwd: bool = True,
    include_timeout: bool = True,
) -> None:
    if include_cwd:
        parser.add_argument("--cwd", default=resolve_hostexec_cwd(), help="Windows working directory")
    if include_timeout:
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=resolve_hostexec_timeout_ms(),
            help="HostExec timeout in milliseconds",
        )


def add_remote_python_argument(
    parser: ArgumentParser,
    *,
    required: bool = False,
) -> None:
    default = resolve_remote_python()
    parser.add_argument(
        "--remote-python",
        required=required and not bool(default),
        default=default,
        help="Remote Python executable path on the Windows VM",
    )


def add_remote_powershell_argument(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--remote-powershell",
        default=resolve_remote_powershell(),
        help="Remote PowerShell executable path on the Windows VM",
    )
