#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_URL = "http://192.168.1.212:8888/"
DEFAULT_ADDR = "0x004011C9"


def api_get(base_url: str, endpoint: str, params: dict[str, str] | None = None, timeout: float = 5.0) -> Any:
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(params)
    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}{query}"
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace").strip()
        content_type = response.headers.get("Content-Type", "").lower()
    if "application/json" in content_type or body.startswith("{") or body.startswith("["):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body
    return body


def health_check(base_url: str) -> dict[str, Any]:
    response = api_get(base_url, "healthz", timeout=5.0)
    if not isinstance(response, dict):
        raise RuntimeError(f"unexpected health response: {response!r}")
    return response


def exec_command(base_url: str, command: str) -> dict[str, Any]:
    response = api_get(base_url, "ExecCommand", {"cmd": command}, timeout=10.0)
    if not isinstance(response, dict):
        return {"success": False, "raw": response}
    return response


def set_breakpoint(base_url: str, addr: str) -> Any:
    return api_get(base_url, "Debug/SetBreakpoint", {"addr": addr}, timeout=10.0)


def delete_breakpoint(base_url: str, addr: str) -> Any:
    return api_get(base_url, "Debug/DeleteBreakpoint", {"addr": addr}, timeout=10.0)


def get_breakpoint(base_url: str, addr: str) -> dict[str, Any] | None:
    target = addr.lower().removeprefix("0x")
    last_response: Any = None
    for _ in range(5):
        response = api_get(base_url, "Breakpoint/List", {"type": "all"}, timeout=10.0)
        last_response = response
        if not isinstance(response, dict):
            raise RuntimeError(f"unexpected breakpoint list response: {response!r}")
        for bp in response.get("breakpoints", []):
            bp_addr = str(bp.get("addr", "")).lower().removeprefix("0x")
            if bp_addr == target:
                return bp
        time.sleep(0.2)
    if not isinstance(last_response, dict):
        raise RuntimeError(f"unexpected breakpoint list response: {last_response!r}")
    return None


def try_commands(
    base_url: str,
    addr: str,
    commands: list[str],
    predicate,
) -> tuple[str | None, dict[str, Any] | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for command in commands:
        result = exec_command(base_url, command)
        bp = get_breakpoint(base_url, addr)
        attempts.append(
            {
                "command": command,
                "result": result,
                "breakpoint": bp,
            }
        )
        if not result.get("success"):
            continue
        if bp is not None and predicate(bp):
            return command, bp, attempts
    return None, get_breakpoint(base_url, addr), attempts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe x64dbg breakpoint logging support by trying candidate command-bar commands and verifying the breakpoint fields.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="x64dbgMCP base URL")
    parser.add_argument(
        "--addr",
        default=DEFAULT_ADDR,
        help="Scratch code address used for the probe breakpoint (default: 0x004011C9)",
    )
    parser.add_argument(
        "--keep-breakpoint",
        action="store_true",
        help="Keep the probe breakpoint instead of deleting it at the end",
    )
    args = parser.parse_args()

    summary: dict[str, Any] = {
        "url": args.url,
        "addr": args.addr,
        "health": None,
        "existingBreakpoint": None,
        "createdProbeBreakpoint": False,
        "probes": {},
        "finalBreakpoint": None,
        "cleanup": None,
    }

    try:
        summary["health"] = health_check(args.url)
    except (RuntimeError, urllib.error.URLError, TimeoutError) as exc:
        summary["error"] = f"health check failed: {exc}"
        print(json.dumps(summary, indent=2, ensure_ascii=True))
        return 1

    existing_bp = get_breakpoint(args.url, args.addr)
    summary["existingBreakpoint"] = existing_bp
    if existing_bp is None:
        set_result = set_breakpoint(args.url, args.addr)
        summary["createdProbeBreakpoint"] = True
        summary["setBreakpointResult"] = set_result
    else:
        summary["note"] = "probe address already had a breakpoint; reusing it for capability detection"

    # `bpcnd` has already been confirmed live in this project, but keep one
    # fallback alias so the script can self-check a fresh session.
    condition_candidates = [
        f"bpcnd {args.addr},1",
        f"SetBreakpointCondition {args.addr},1",
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        condition_candidates,
        lambda item: str(item.get("breakCondition", "")).strip() == "1",
    )
    summary["probes"]["breakCondition"] = {
        "selectedCommand": cmd,
        "candidates": condition_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    fast_resume_candidates = [
        f"SetBreakpointFastResume {args.addr},1",
        f"bpfastresume {args.addr},1",
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        fast_resume_candidates,
        lambda item: bool(item.get("fastResume")),
    )
    summary["probes"]["fastResume"] = {
        "selectedCommand": cmd,
        "candidates": fast_resume_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    silent_candidates = [
        f"SetBreakpointSilent {args.addr},1",
        f"bpsilent {args.addr},1",
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        silent_candidates,
        lambda item: bool(item.get("silent")),
    )
    summary["probes"]["silent"] = {
        "selectedCommand": cmd,
        "candidates": silent_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    log_text = "probe_writer_log"
    log_candidates = [
        f'SetBreakpointLog {args.addr},"{log_text}"',
        f'bplog {args.addr},"{log_text}"',
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        log_candidates,
        lambda item: str(item.get("logText", "")) == log_text,
    )
    summary["probes"]["logText"] = {
        "selectedCommand": cmd,
        "candidates": log_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    command_text = 'log "probe_cmd"'
    command_candidates = [
        f'SetBreakpointCommand {args.addr},"{command_text}"',
        f'bpcmd {args.addr},"{command_text}"',
        f'bpcommand {args.addr},"{command_text}"',
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        command_candidates,
        lambda item: str(item.get("commandText", "")) == command_text,
    )
    summary["probes"]["commandText"] = {
        "selectedCommand": cmd,
        "candidates": command_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    command_condition_candidates = [
        f"SetBreakpointCommandCondition {args.addr},1",
        f"bpcmdcond {args.addr},1",
        f"bpcommandcondition {args.addr},1",
    ]
    cmd, bp, attempts = try_commands(
        args.url,
        args.addr,
        command_condition_candidates,
        lambda item: str(item.get("commandText", "")) == command_text,
    )
    summary["probes"]["commandCondition"] = {
        "selectedCommand": cmd,
        "candidates": command_condition_candidates,
        "attempts": attempts,
        "breakpoint": bp,
    }

    summary["finalBreakpoint"] = get_breakpoint(args.url, args.addr)

    if summary["createdProbeBreakpoint"] and not args.keep_breakpoint:
        summary["cleanup"] = delete_breakpoint(args.url, args.addr)

    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
