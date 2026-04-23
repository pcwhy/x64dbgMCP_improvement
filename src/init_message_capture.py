#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


DEFAULT_CONTEXT_ITEMS = (
    "retaddr=[esp];"
    "msg_ptr=[esp+4];"
    "msg_hwnd=[[esp+4]];"
    "msg_message=[[esp+4]+4];"
    "msg_wparam=[[esp+4]+8];"
    "msg_lparam=[[esp+4]+0xC];"
    "msg_time=[[esp+4]+0x10];"
    "msg_x=[[[esp+4]+0x14]];"
    "msg_y=[[[esp+4]+0x14]+4]"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize generic message-loop capture breakpoints in x64dbg.",
    )
    parser.add_argument("--x64dbg-url", required=True, help="x64dbg HTTP bridge URL")
    parser.add_argument("--translate-addr", required=True, help="Address of TranslateMessage")
    parser.add_argument("--peek-addr", default="", help="Address of PeekMessageW/PeekMessageA")
    parser.add_argument("--dispatch-addr", default="", help="Address used as a DispatchMessage marker")
    parser.add_argument(
        "--context-items",
        default=DEFAULT_CONTEXT_ITEMS,
        help="Semicolon-separated watched expressions appended to breakpoint events.",
    )
    parser.add_argument("--no-clear-log", action="store_true", help="Do not clear the event log after setup.")
    return parser.parse_args()


def configure_breakpoint(x64dbg, addr: str, name: str, log_text: str) -> dict[str, object]:
    steps = [
        x64dbg.BreakpointSet(addr),
        x64dbg.BreakpointSetName(addr, name),
        x64dbg.BreakpointSetCondition(addr, "1"),
        x64dbg.BreakpointSetLog(addr, log_text),
        x64dbg.BreakpointSetLogCondition(addr, ""),
        x64dbg.BreakpointSetCommand(addr, "$breakpointcondition=0"),
        x64dbg.BreakpointSetCommandCondition(addr, ""),
        x64dbg.BreakpointSetFastResume(addr, "false"),
        x64dbg.BreakpointSetSingleshoot(addr, "false"),
        x64dbg.BreakpointSetSilent(addr, True),
        x64dbg.BreakpointSetEnabled(addr, "true"),
        x64dbg.BreakpointGet(addr),
    ]
    return {
        "addr": addr,
        "name": name,
        "logText": log_text,
        "steps": steps,
        "final": steps[-1],
    }


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(args.x64dbg_url)

    configured = []
    context_result = x64dbg.SetBreakpointContextExpressions(args.context_items)
    configured.append(configure_breakpoint(x64dbg, args.translate_addr, "msg_translate", "MSG_Translate"))
    if args.peek_addr:
        configured.append(configure_breakpoint(x64dbg, args.peek_addr, "msg_peek", "MSG_PeekW"))
    if args.dispatch_addr:
        configured.append(configure_breakpoint(x64dbg, args.dispatch_addr, "msg_dispatch_marker", "MSG_DispatchMarker"))

    clear_result = None if args.no_clear_log else x64dbg.ClearLog()
    print(json.dumps({
        "success": True,
        "context": context_result,
        "breakpoints": configured,
        "clearLog": clear_result,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
