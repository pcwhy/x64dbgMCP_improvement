#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import json
import platform
import time
from pathlib import Path


MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay a replay-ish message export using basic cursor moves and left-click events.",
    )
    parser.add_argument("input_json", type=Path, help="Replay-ish export JSON from export_message_replayish.py")
    parser.add_argument(
        "--sleep-scale",
        type=float,
        default=1.0,
        help="Scale factor applied to recorded action delays.",
    )
    parser.add_argument(
        "--min-move-duration-ms",
        type=float,
        default=10.0,
        help="Minimum sleep after a move segment, in milliseconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the replay plan without sending input events.",
    )
    return parser.parse_args()


def load_actions(path: Path) -> list[dict[str, object]]:
    with path.open() as fh:
        payload = json.load(fh)
    actions = payload.get("actions")
    if not isinstance(actions, list):
        raise ValueError("input JSON does not contain an actions list")
    return actions


def action_delay_ms(prev_action: dict[str, object] | None, action: dict[str, object]) -> int:
    if prev_action is None:
        return 0
    prev_tick = (
        prev_action.get("end_tick_ms")
        if prev_action.get("type") == "move_segment"
        else prev_action.get("tick_ms")
    )
    cur_tick = (
        action.get("start_tick_ms")
        if action.get("type") == "move_segment"
        else action.get("tick_ms")
    )
    if prev_tick is None or cur_tick is None:
        return 0
    return max(0, int(cur_tick) - int(prev_tick))


def move_cursor(x: int, y: int) -> None:
    ctypes.windll.user32.SetCursorPos(int(x), int(y))


def mouse_event(flags: int) -> None:
    ctypes.windll.user32.mouse_event(flags, 0, 0, 0, 0)


def replay_actions(
    actions: list[dict[str, object]],
    *,
    sleep_scale: float,
    min_move_duration_ms: float,
    dry_run: bool,
) -> None:
    if not dry_run and platform.system() != "Windows":
        raise RuntimeError("live replay currently only supports Windows; use --dry-run elsewhere")

    prev_action: dict[str, object] | None = None
    for action in actions:
        delay_ms = action_delay_ms(prev_action, action)
        scaled_delay = max(0.0, delay_ms * sleep_scale / 1000.0)
        if dry_run:
            print(f"delay {delay_ms}ms -> {scaled_delay:.3f}s before {action['type']}")
        elif scaled_delay > 0:
            time.sleep(scaled_delay)

        action_type = action["type"]
        if action_type == "move_segment":
            x = action.get("end_x")
            y = action.get("end_y")
            if dry_run:
                print(
                    f"move_segment {action.get('start_seq')}..{action.get('end_seq')} "
                    f"to ({x}, {y}) duration={action.get('duration_ms')}ms "
                    f"points={action.get('point_count')}"
                )
            else:
                move_cursor(int(x), int(y))
                move_sleep = max(min_move_duration_ms, float(action.get("duration_ms") or 0.0))
                time.sleep(move_sleep * sleep_scale / 1000.0)
        elif action_type == "left_down":
            x = action.get("x")
            y = action.get("y")
            if dry_run:
                print(f"left_down seq={action.get('seq')} at ({x}, {y})")
            else:
                move_cursor(int(x), int(y))
                mouse_event(MOUSEEVENTF_LEFTDOWN)
        elif action_type == "left_up":
            x = action.get("x")
            y = action.get("y")
            if dry_run:
                print(f"left_up seq={action.get('seq')} at ({x}, {y})")
            else:
                move_cursor(int(x), int(y))
                mouse_event(MOUSEEVENTF_LEFTUP)
        else:
            if dry_run:
                print(f"skip {action_type} seq={action.get('seq')}")

        prev_action = action


def main() -> None:
    args = parse_args()
    actions = load_actions(args.input_json)
    replay_actions(
        actions,
        sleep_scale=args.sleep_scale,
        min_move_duration_ms=args.min_move_duration_ms,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
