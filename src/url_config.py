#!/usr/bin/env python3
from __future__ import annotations

import os
from argparse import ArgumentParser


DEFAULT_LOCAL_X64DBG_URL = "http://127.0.0.1:8888/"


def resolve_x64dbg_url(default: str = DEFAULT_LOCAL_X64DBG_URL) -> str:
    env_url = os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http"):
        return env_url
    return default


def add_x64dbg_url_argument(
    parser: ArgumentParser,
    *,
    default: str = DEFAULT_LOCAL_X64DBG_URL,
    dest: str = "url",
    help_text: str = "x64dbgMCP base URL",
) -> None:
    parser.add_argument(
        "--url",
        "--x64dbg-url",
        dest=dest,
        default=resolve_x64dbg_url(default),
        help=help_text,
    )
