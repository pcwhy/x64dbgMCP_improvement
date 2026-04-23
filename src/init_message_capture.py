#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
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
    parser.add_argument(
        "--settle-ms",
        type=int,
        default=120,
        help="Sleep briefly after each breakpoint mutation to let x64dbg state settle.",
    )
    parser.add_argument(
        "--verify-timeout-ms",
        type=int,
        default=3000,
        help="How long to wait for the final breakpoint state to match expectations.",
    )
    parser.add_argument("--no-clear-log", action="store_true", help="Do not clear the event log after setup.")
    return parser.parse_args()


def _sleep_ms(settle_ms: int) -> None:
    if settle_ms > 0:
        time.sleep(settle_ms / 1000.0)


def _matches_expected(final_state: dict[str, object], *, name: str, log_text: str) -> bool:
    if not isinstance(final_state, dict):
        return False
    if final_state.get("enabled") is not True:
        return False
    if final_state.get("name") != name:
        return False
    if final_state.get("breakCondition") != "1":
        return False
    if final_state.get("logText") != log_text:
        return False
    if final_state.get("commandText") != "$breakpointcondition=0":
        return False
    if final_state.get("silent") is not True:
        return False
    return True


def _poll_breakpoint(x64dbg, addr: str, *, name: str, log_text: str, verify_timeout_ms: int, settle_ms: int) -> tuple[dict[str, object], bool]:
    deadline = time.time() + max(0, verify_timeout_ms) / 1000.0
    last_state: dict[str, object] = {}
    while True:
        state = x64dbg.BreakpointGet(addr)
        if isinstance(state, dict):
            last_state = state
            if _matches_expected(state, name=name, log_text=log_text):
                return state, True
        if time.time() >= deadline:
            return last_state, False
        _sleep_ms(max(20, settle_ms))


def configure_breakpoint(
    x64dbg,
    addr: str,
    name: str,
    log_text: str,
    *,
    settle_ms: int,
    verify_timeout_ms: int,
) -> dict[str, object]:
    steps = []
    mutators = [
        ("set", lambda: x64dbg.BreakpointSet(addr)),
        ("name", lambda: x64dbg.BreakpointSetName(addr, name)),
        ("condition", lambda: x64dbg.BreakpointSetCondition(addr, "1")),
        ("log", lambda: x64dbg.BreakpointSetLog(addr, log_text)),
        ("log_condition", lambda: x64dbg.BreakpointSetLogCondition(addr, "")),
        ("command", lambda: x64dbg.BreakpointSetCommand(addr, "$breakpointcondition=0")),
        ("command_condition", lambda: x64dbg.BreakpointSetCommandCondition(addr, "")),
        ("fast_resume", lambda: x64dbg.BreakpointSetFastResume(addr, "false")),
        ("singleshoot", lambda: x64dbg.BreakpointSetSingleshoot(addr, "false")),
        ("silent", lambda: x64dbg.BreakpointSetSilent(addr, True)),
        ("enabled", lambda: x64dbg.BreakpointSetEnabled(addr, "true")),
    ]
    for label, fn in mutators:
        result = fn()
        steps.append({"step": label, "result": result})
        _sleep_ms(settle_ms)

    final_state, verified = _poll_breakpoint(
        x64dbg,
        addr,
        name=name,
        log_text=log_text,
        verify_timeout_ms=verify_timeout_ms,
        settle_ms=settle_ms,
    )
    return {
        "addr": addr,
        "name": name,
        "logText": log_text,
        "steps": steps,
        "verified": verified,
        "final": final_state,
    }


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(args.x64dbg_url)

    configured = []
    context_result = x64dbg.SetBreakpointContextExpressions(args.context_items)
    _sleep_ms(args.settle_ms)
    configured.append(
        configure_breakpoint(
            x64dbg,
            args.translate_addr,
            "msg_translate",
            "MSG_Translate",
            settle_ms=args.settle_ms,
            verify_timeout_ms=args.verify_timeout_ms,
        )
    )
    if args.peek_addr:
        configured.append(
            configure_breakpoint(
                x64dbg,
                args.peek_addr,
                "msg_peek",
                "MSG_PeekW",
                settle_ms=args.settle_ms,
                verify_timeout_ms=args.verify_timeout_ms,
            )
        )
    if args.dispatch_addr:
        configured.append(
            configure_breakpoint(
                x64dbg,
                args.dispatch_addr,
                "msg_dispatch_marker",
                "MSG_DispatchMarker",
                settle_ms=args.settle_ms,
                verify_timeout_ms=args.verify_timeout_ms,
            )
        )

    clear_result = None if args.no_clear_log else x64dbg.ClearLog()
    print(json.dumps({
        "success": all(bp.get("verified") for bp in configured),
        "context": context_result,
        "breakpoints": configured,
        "clearLog": clear_result,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
