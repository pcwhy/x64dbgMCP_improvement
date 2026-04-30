#!/usr/bin/env python3
"""Forward a LAN-visible TCP port to x64dbg's localhost-only HTTP plugin.

Run this inside the Windows VM where x64dbg is running. The x64dbg MCP/HTTP
plugin listens on 127.0.0.1:8888, which cannot be reached from macOS directly.
This helper exposes 0.0.0.0:8889 and forwards traffic to 127.0.0.1:8888.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from datetime import datetime


STARTED_AT = time.time()
ACTIVE_CONNECTIONS = 0
ACTIVE_CONNECTIONS_LOCK = threading.Lock()


def connection_delta(delta: int) -> int:
    global ACTIVE_CONNECTIONS
    with ACTIVE_CONNECTIONS_LOCK:
        ACTIVE_CONNECTIONS += delta
        return ACTIVE_CONNECTIONS


def log(message: str, **fields: object) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    suffix = ""
    if fields:
        suffix = " " + " ".join("%s=%r" % (key, value) for key, value in fields.items())
    print("[%s] %s%s" % (timestamp, message, suffix), flush=True)


def http_response(status: str, body: bytes, content_type: str = "application/json") -> bytes:
    return (
        ("HTTP/1.1 %s\r\n" % status).encode("ascii")
        + ("Content-Type: %s\r\n" % content_type).encode("ascii")
        + ("Content-Length: %d\r\n" % len(body)).encode("ascii")
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )


def recv_initial_request(client: socket.socket) -> bytes:
    client.settimeout(2)
    chunks = []
    total = 0
    while b"\r\n\r\n" not in b"".join(chunks) and total < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if len(chunk) < 4096:
            break
    return b"".join(chunks)


def request_path(request: bytes) -> str:
    first = request.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    parts = first.split()
    if len(parts) >= 2:
        return parts[1]
    return ""


def target_probe(target_host: str, target_port: int) -> dict:
    request = b"GET /GetModuleList HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    started = time.time()
    try:
        with socket.create_connection((target_host, target_port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(request)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
        elapsed_ms = int((time.time() - started) * 1000)
        first_line = data.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        ok = first_line.startswith("HTTP/1.") and " 200 " in first_line
        return {
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "status_line": first_line,
            "first_bytes": data[:160].decode("latin1", errors="replace"),
        }
    except (OSError, TimeoutError) as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "ok": False,
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
        }


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        src.settimeout(30)
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def handle_client(client: socket.socket, target_host: str, target_port: int) -> None:
    request_started = time.time()
    peer = "unknown"
    try:
        host, port = client.getpeername()[:2]
        peer = "%s:%s" % (host, port)
    except OSError:
        pass
    active = connection_delta(1)
    try:
        initial = recv_initial_request(client)
    except OSError as exc:
        elapsed_ms = int((time.time() - request_started) * 1000)
        log("request-read-failed", peer=peer, elapsed_ms=elapsed_ms, error=str(exc))
        client.close()
        connection_delta(-1)
        return

    path = request_path(initial)
    log("request-start", peer=peer, path=path or "<unknown>", active=active)

    if path in ("/health", "/healthz", "/metrics", "/"):
        body = json.dumps(
            {
                "ok": True,
                "service": "x64dbg_forward",
                "listen": "0.0.0.0",
                "target": "%s:%d" % (target_host, target_port),
                "active_connections": ACTIVE_CONNECTIONS,
                "uptime_seconds": int(time.time() - STARTED_AT),
            },
            sort_keys=True,
        ).encode("utf-8")
        client.sendall(http_response("200 OK", body))
        client.close()
        elapsed_ms = int((time.time() - request_started) * 1000)
        log("request-finish", peer=peer, path=path, status="200 OK", elapsed_ms=elapsed_ms)
        connection_delta(-1)
        return

    if path == "/target-health":
        probe = target_probe(target_host, target_port)
        status = "200 OK" if probe.get("ok") else "502 Bad Gateway"
        body = json.dumps(
            {
                "ok": bool(probe.get("ok")),
                "service": "x64dbg_forward",
                "target_probe": probe,
            },
            sort_keys=True,
        ).encode("utf-8")
        client.sendall(http_response(status, body))
        client.close()
        elapsed_ms = int((time.time() - request_started) * 1000)
        log(
            "request-finish",
            peer=peer,
            path=path,
            status=status,
            elapsed_ms=elapsed_ms,
            target_ok=probe.get("ok"),
            target_error=probe.get("error"),
            target_status=probe.get("status_line"),
        )
        connection_delta(-1)
        return

    try:
        target = socket.create_connection((target_host, target_port), timeout=5)
        target.settimeout(30)
    except OSError as exc:
        elapsed_ms = int((time.time() - request_started) * 1000)
        log(
            "target-connect-failed",
            peer=peer,
            path=path,
            target="%s:%d" % (target_host, target_port),
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )
        client.close()
        connection_delta(-1)
        return

    if initial:
        try:
            target.sendall(initial)
        except OSError as exc:
            elapsed_ms = int((time.time() - request_started) * 1000)
            log("target-send-failed", peer=peer, path=path, elapsed_ms=elapsed_ms, error=str(exc))
            client.close()
            target.close()
            connection_delta(-1)
            return

    def wrapped_pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            pipe(src, dst)
        finally:
            connection_delta(-1)

    # One active client creates two pipe threads. The counter is adjusted so
    # both directions are visible, without leaving the accepted client counted.
    connection_delta(1)
    threading.Thread(target=wrapped_pipe, args=(client, target), daemon=True).start()
    threading.Thread(target=wrapped_pipe, args=(target, client), daemon=True).start()
    elapsed_ms = int((time.time() - request_started) * 1000)
    log(
        "request-forwarded",
        peer=peer,
        path=path,
        target="%s:%d" % (target_host, target_port),
        elapsed_ms=elapsed_ms,
        active=ACTIVE_CONNECTIONS,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8889)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=8888)
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.listen_host, args.listen_port))
    server.settimeout(0.5)
    server.listen(20)

    log(
        "server-start",
        listen="%s:%d" % (args.listen_host, args.listen_port),
        target="%s:%d" % (args.target_host, args.target_port),
    )
    log("server-health-url", self="http://<vm-ip>:%d/health" % args.listen_port)
    log("server-health-url", target="http://<vm-ip>:%d/target-health" % args.listen_port)
    log("server-ready", note="Press Ctrl+C to stop.")

    try:
        while True:
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            log("client-accepted", peer="%s:%d" % addr, active=ACTIVE_CONNECTIONS)
            thread = threading.Thread(
                target=handle_client,
                args=(client, args.target_host, args.target_port),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        log("server-stop-requested", reason="KeyboardInterrupt")
    finally:
        server.close()
        log("server-stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
