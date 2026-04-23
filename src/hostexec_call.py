#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Small helper for calling x64dbg HostExec/HostSpawn.")
    parser.add_argument("--x64dbg-url", required=True, help="x64dbg HTTP bridge URL")
    parser.add_argument("--mode", choices=["exec", "spawn"], default="exec", help="Whether to use HostExec or HostSpawn")
    parser.add_argument("--program", required=True, help="Windows executable path")
    parser.add_argument("--args", default="", help="Raw Windows command-line tail")
    parser.add_argument("--cwd", default="", help="Windows working directory")
    parser.add_argument("--timeout-ms", type=int, default=30000, help="HostExec timeout in milliseconds")
    opts = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(opts.x64dbg_url)
    if opts.mode == "spawn":
        result = x64dbg.HostSpawn(opts.program, opts.args, opts.cwd)
    else:
        result = x64dbg.HostExec(opts.program, opts.args, opts.cwd, opts.timeout_ms)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
