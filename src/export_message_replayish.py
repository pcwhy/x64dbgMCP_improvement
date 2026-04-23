#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


BREAKPOINT_FIELD_RE = re.compile(r"(\w+)=([^ ]+)")

DEFAULT_RELEVANT_MESSAGES = {
    "0x200",  # WM_MOUSEMOVE
    "0x201",  # WM_LBUTTONDOWN
    "0x202",  # WM_LBUTTONUP
    "0xA0",   # WM_NCMOUSEMOVE
}

MESSAGE_NAMES = {
    "0x5": "WM_SIZE",
    "0x6": "WM_ACTIVATE",
    "0x7": "WM_SETFOCUS",
    "0x8": "WM_KILLFOCUS",
    "0x10": "WM_CLOSE",
    "0xF": "WM_PAINT",
    "0x111": "WM_COMMAND",
    "0x113": "WM_TIMER",
    "0x200": "WM_MOUSEMOVE",
    "0x201": "WM_LBUTTONDOWN",
    "0x202": "WM_LBUTTONUP",
    "0x203": "WM_LBUTTONDBLCLK",
    "0x204": "WM_RBUTTONDOWN",
    "0x205": "WM_RBUTTONUP",
    "0xA0": "WM_NCMOUSEMOVE",
    "0x2A2": "WM_NCMOUSELEAVE",
    "0x405": "WM_USER+0x5",
    "0x407": "WM_USER+0x7",
    "0xC03E": "UNKNOWN_DIALOGISH_0xC03E",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export replay-ish user interaction events from x64dbg message-loop captures.",
    )
    parser.add_argument("input_json", type=Path, help="Full /Log/Recent capture JSON")
    parser.add_argument(
        "--output-prefix",
        type=Path,
        default=None,
        help="Output prefix for exported JSON/Markdown. Defaults next to input with _export suffix.",
    )
    parser.add_argument(
        "--include-peek",
        action="store_true",
        help="Include MSG_PeekW entries in the exported event stream.",
    )
    parser.add_argument(
        "--include-dispatch-marker",
        action="store_true",
        help="Include MSG_DispatchMarker entries in the exported event stream.",
    )
    parser.add_argument(
        "--keep-message",
        action="append",
        default=None,
        help="Additional message code to keep, e.g. 0x113. May be repeated.",
    )
    return parser.parse_args()


def parse_breakpoint_text(text: str) -> dict[str, str]:
    return {key: value for key, value in BREAKPOINT_FIELD_RE.findall(text)}


def parse_hex_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def parse_log_entries(path: Path) -> list[dict[str, object]]:
    with path.open() as fh:
        payload = json.load(fh)
    rows: list[dict[str, object]] = []
    for entry in payload.get("entries", []):
        text = entry.get("text", "")
        if not isinstance(text, str) or "logText=" not in text:
            continue
        fields = parse_breakpoint_text(text)
        log_label = fields.get("logText")
        if not log_label:
            continue
        rows.append(
            {
                "seq": entry.get("seq"),
                "tick_ms": entry.get("tickMs"),
                "kind": entry.get("kind"),
                "log_label": log_label,
                "fields": fields,
            }
        )
    return rows


def classify_message_name(message_code: str | None) -> str | None:
    if not message_code:
        return None
    return MESSAGE_NAMES.get(message_code, f"UNKNOWN_{message_code}")


def is_move_event(event: dict[str, object]) -> bool:
    return event.get("msg") in {"0x200", "0xA0"}


def build_replayish_events(
    entries: list[dict[str, object]],
    *,
    relevant_messages: set[str],
    include_peek: bool,
    include_dispatch_marker: bool,
) -> list[dict[str, object]]:
    exported: list[dict[str, object]] = []
    for row in entries:
        fields = row["fields"]
        assert isinstance(fields, dict)
        log_label = row["log_label"]
        assert isinstance(log_label, str)

        if log_label == "MSG_Translate":
            msg = fields.get("msg_message")
            if msg not in relevant_messages:
                continue
        elif log_label == "MSG_PeekW":
            if not include_peek:
                continue
        elif log_label == "MSG_DispatchMarker":
            if not include_dispatch_marker:
                continue
        else:
            continue

        msg_code = fields.get("msg_message")
        exported.append(
            {
                "seq": row.get("seq"),
                "tick_ms": row.get("tick_ms"),
                "source": log_label,
                "hwnd": fields.get("msg_hwnd"),
                "msg": msg_code,
                "msg_name": classify_message_name(msg_code),
                "wparam": fields.get("msg_wparam"),
                "lparam": fields.get("msg_lparam"),
                "x": parse_hex_int(fields.get("msg_x")),
                "y": parse_hex_int(fields.get("msg_y")),
                "retaddr": fields.get("retaddr"),
                "stack_arg0": fields.get("stk_arg0"),
                "stack_arg1": fields.get("stk_arg1"),
                "stack_arg2": fields.get("stk_arg2"),
                "stack_arg3": fields.get("stk_arg3"),
            }
        )
    return exported


def build_replayish_actions(events: list[dict[str, object]]) -> list[dict[str, object]]:
    actions: list[dict[str, object]] = []
    i = 0
    while i < len(events):
        event = events[i]
        if is_move_event(event):
            j = i + 1
            last = event
            hwnds = {event.get("hwnd")}
            msgs = {event.get("msg")}
            while j < len(events) and is_move_event(events[j]):
                last = events[j]
                hwnds.add(events[j].get("hwnd"))
                msgs.add(events[j].get("msg"))
                j += 1
            actions.append(
                {
                    "type": "move_segment",
                    "start_seq": event.get("seq"),
                    "end_seq": last.get("seq"),
                    "start_tick_ms": event.get("tick_ms"),
                    "end_tick_ms": last.get("tick_ms"),
                    "duration_ms": max(0, (last.get("tick_ms") or 0) - (event.get("tick_ms") or 0)),
                    "start_x": event.get("x"),
                    "start_y": event.get("y"),
                    "end_x": last.get("x"),
                    "end_y": last.get("y"),
                    "point_count": j - i,
                    "hwnds": sorted(hwnd for hwnd in hwnds if hwnd),
                    "messages": sorted(msg for msg in msgs if msg),
                }
            )
            i = j
            continue

        msg = event.get("msg")
        if msg == "0x201":
            action_type = "left_down"
        elif msg == "0x202":
            action_type = "left_up"
        else:
            action_type = "message"
        actions.append(
            {
                "type": action_type,
                "seq": event.get("seq"),
                "tick_ms": event.get("tick_ms"),
                "hwnd": event.get("hwnd"),
                "msg": event.get("msg"),
                "msg_name": event.get("msg_name"),
                "wparam": event.get("wparam"),
                "lparam": event.get("lparam"),
                "x": event.get("x"),
                "y": event.get("y"),
            }
        )
        i += 1
    return compress_replayish_actions(actions)


def is_zero_displacement_move_segment(action: dict[str, object]) -> bool:
    return (
        action.get("type") == "move_segment"
        and action.get("start_x") == action.get("end_x")
        and action.get("start_y") == action.get("end_y")
    )


def compress_replayish_actions(actions: list[dict[str, object]]) -> list[dict[str, object]]:
    compressed: list[dict[str, object]] = []
    for index, action in enumerate(actions):
        if is_zero_displacement_move_segment(action):
            has_neighbor = index > 0 or index + 1 < len(actions)
            if has_neighbor:
                continue
        compressed.append(action)
    return compressed


def summarize_events(events: list[dict[str, object]], actions: list[dict[str, object]]) -> dict[str, object]:
    by_source = Counter(event["source"] for event in events)
    by_msg = Counter(event["msg"] for event in events if event.get("msg"))
    by_hwnd = Counter(event["hwnd"] for event in events if event.get("hwnd"))
    by_action_type = Counter(action["type"] for action in actions if action.get("type"))
    return {
        "exported_count": len(events),
        "action_count": len(actions),
        "by_source": dict(by_source),
        "by_msg": dict(by_msg),
        "by_hwnd": dict(by_hwnd),
        "by_action_type": dict(by_action_type),
    }


def render_summary_markdown(
    input_json: Path,
    exported_json: Path,
    events: list[dict[str, object]],
    actions: list[dict[str, object]],
    summary: dict[str, object],
) -> str:
    lines = [
        f"Replay-ish export from `{input_json}`",
        "",
        f"- Exported JSON: `{exported_json}`",
        f"- Exported event count: `{summary['exported_count']}`",
        f"- Compressed action count: `{summary['action_count']}`",
        "",
        "Top message counts:",
    ]
    by_msg = Counter(summary["by_msg"])
    for code, count in by_msg.most_common(10):
        lines.append(f"- `{code}` {classify_message_name(code)}: `{count}`")
    lines.extend(["", "Top target windows:"])
    by_hwnd = Counter(summary["by_hwnd"])
    for hwnd, count in by_hwnd.most_common(10):
        lines.append(f"- `{hwnd}`: `{count}`")
    lines.extend(["", "Compressed action counts:"])
    by_action_type = Counter(summary["by_action_type"])
    for action_type, count in by_action_type.most_common(10):
        lines.append(f"- `{action_type}`: `{count}`")
    lines.extend(["", "Representative actions:"])
    for action in actions[:20]:
        if action["type"] == "move_segment":
            lines.append(
                "- "
                f"move_segment seq={action['start_seq']}..{action['end_seq']} "
                f"from=({action['start_x']},{action['start_y']}) "
                f"to=({action['end_x']},{action['end_y']}) "
                f"duration_ms={action['duration_ms']} points={action['point_count']}"
            )
        else:
            lines.append(
                "- "
                f"{action['type']} seq={action['seq']} hwnd={action['hwnd']} "
                f"msg={action['msg']} {action['msg_name']} "
                f"x={action['x']} y={action['y']}"
            )
    lines.extend(["", "Representative events:"])
    for event in events[:20]:
        lines.append(
            "- "
            f"seq={event['seq']} source={event['source']} hwnd={event['hwnd']} "
            f"msg={event['msg']} {event['msg_name']} "
            f"x={event['x']} y={event['y']} wParam={event['wparam']} lParam={event['lparam']}"
        )
    return "\n".join(lines) + "\n"


def default_output_prefix(input_json: Path) -> Path:
    return input_json.with_name(input_json.stem + "_export")


def main() -> None:
    args = parse_args()
    output_prefix = args.output_prefix or default_output_prefix(args.input_json)
    relevant_messages = set(DEFAULT_RELEVANT_MESSAGES)
    if args.keep_message:
        relevant_messages.update(args.keep_message)

    entries = parse_log_entries(args.input_json)
    exported_events = build_replayish_events(
        entries,
        relevant_messages=relevant_messages,
        include_peek=args.include_peek,
        include_dispatch_marker=args.include_dispatch_marker,
    )
    exported_actions = build_replayish_actions(exported_events)
    summary = summarize_events(exported_events, exported_actions)

    exported_json = output_prefix.with_suffix(".json")
    exported_md = output_prefix.with_suffix(".md")

    with exported_json.open("w") as fh:
        json.dump(
            {
                "input_json": str(args.input_json),
                "relevant_messages": sorted(relevant_messages),
                "include_peek": args.include_peek,
                "include_dispatch_marker": args.include_dispatch_marker,
                "summary": summary,
                "events": exported_events,
                "actions": exported_actions,
            },
            fh,
            indent=2,
        )

    exported_md.write_text(
        render_summary_markdown(args.input_json, exported_json, exported_events, exported_actions, summary)
    )

    print(f"Exported {len(exported_events)} replay-ish events")
    print(f"JSON: {exported_json}")
    print(f"Markdown: {exported_md}")


if __name__ == "__main__":
    main()
