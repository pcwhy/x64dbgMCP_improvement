#!/usr/bin/env python3
from __future__ import annotations

import base64
import json


def chunk_bytes(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def b64_text(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def parse_job_json_output(output: str, *, step: str) -> dict:
    try:
        parsed = json.loads(output.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{step}: invalid JSON output: {output!r}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{step}: expected JSON object output, got: {parsed!r}")
    return parsed


def require_existing_remote_file(metadata: dict, *, step: str) -> None:
    if metadata.get("exists") is not True:
        raise RuntimeError(f"{step}: remote file missing: {json.dumps(metadata, ensure_ascii=False)}")


def require_size_and_sha256_match(
    *,
    local_size: int,
    local_sha256: str,
    remote_size: int,
    remote_sha256: str,
    step: str,
) -> None:
    if local_size != remote_size:
        raise RuntimeError(f"{step}: size mismatch local={local_size} remote={remote_size}")
    if local_sha256 != remote_sha256:
        raise RuntimeError(
            f"{step}: sha256 mismatch local={local_sha256} remote={remote_sha256}"
        )
