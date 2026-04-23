#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch a message-capture log from x64dbg and save it to disk.",
    )
    parser.add_argument("--x64dbg-url", required=True, help="x64dbg HTTP bridge URL")
    parser.add_argument("--output-json", type=Path, required=True, help="Destination for /Log/Recent JSON")
    parser.add_argument(
        "--output-breakpoints",
        type=Path,
        default=None,
        help="Optional destination for /Breakpoint/List JSON",
    )
    parser.add_argument("--since", type=int, default=0, help="Minimum event sequence number to include")
    parser.add_argument("--limit", type=int, default=-1, help="Maximum number of events to fetch; -1 means all")
    parser.add_argument(
        "--tail",
        action="store_true",
        help="Use newest-first truncation instead of forward pagination semantics.",
    )
    parser.add_argument("--clear", action="store_true", help="Clear the plugin buffer after reading it.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(args.x64dbg_url)

    log_payload = x64dbg.GetRecentLog(args.limit, args.since, args.clear, args.tail)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(log_payload, indent=2, ensure_ascii=False) + "\n")

    breakpoint_payload = None
    if args.output_breakpoints is not None:
        breakpoint_payload = x64dbg.GetBreakpointList()
        args.output_breakpoints.parent.mkdir(parents=True, exist_ok=True)
        args.output_breakpoints.write_text(json.dumps(breakpoint_payload, indent=2, ensure_ascii=False) + "\n")

    print(json.dumps({
        "success": True,
        "outputJson": str(args.output_json),
        "outputBreakpoints": str(args.output_breakpoints) if args.output_breakpoints else None,
        "logSummary": {
            "count": log_payload.get("count") if isinstance(log_payload, dict) else None,
            "matchedCount": log_payload.get("matchedCount") if isinstance(log_payload, dict) else None,
            "totalBuffered": log_payload.get("totalBuffered") if isinstance(log_payload, dict) else None,
            "hasMore": log_payload.get("hasMore") if isinstance(log_payload, dict) else None,
        },
        "breakpointCount": (
            breakpoint_payload.get("count") if isinstance(breakpoint_payload, dict) else None
        ),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
