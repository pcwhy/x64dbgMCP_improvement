#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path


DEFAULT_CHUNK_SIZE = 3072


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download a file from a Windows VM path through x64dbg HostExec and remote Python.",
    )
    parser.add_argument("--x64dbg-url", required=True, help="x64dbg HTTP bridge URL")
    parser.add_argument("--remote-python", required=True, help="Remote Python executable path on the Windows VM")
    parser.add_argument("--cwd", default="", help="Optional remote working directory")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Raw bytes per downloaded chunk")
    parser.add_argument("--timeout-ms", type=int, default=30000, help="Per-chunk HostExec timeout")
    parser.add_argument("--no-verify", action="store_true", help="Skip final local size/hash verification")
    parser.add_argument("source_path", help="Remote source file path on the Windows VM")
    parser.add_argument("target_file", type=Path, help="Local destination file path")
    return parser.parse_args()


def _b64_text(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_remote_stat_args(source_path: str) -> str:
    path_b64 = _b64_text(source_path.encode("utf-8"))
    code = (
        "import base64,hashlib,json,pathlib;"
        f"p=pathlib.Path(base64.b64decode('{path_b64}').decode('utf-8'));"
        "exists=p.exists();"
        "data=p.read_bytes() if exists else b'';"
        "print(json.dumps({"
        "'exists': exists,"
        "'size': len(data),"
        "'sha256': hashlib.sha256(data).hexdigest() if exists else ''"
        "}))"
    )
    return f'-c "{code}"'


def build_remote_read_chunk_args(source_path: str, offset: int, chunk_size: int) -> str:
    path_b64 = _b64_text(source_path.encode("utf-8"))
    code = (
        "import base64,json,pathlib;"
        f"p=pathlib.Path(base64.b64decode('{path_b64}').decode('utf-8'));"
        f"offset={offset};"
        f"size={chunk_size};"
        "fh=open(p,'rb');"
        "fh.seek(offset);"
        "data=fh.read(size);"
        "fh.close();"
        "print(json.dumps({"
        "'offset': offset,"
        "'size': len(data),"
        "'data_b64': base64.b64encode(data).decode('ascii')"
        "}))"
    )
    return f'-c "{code}"'


def _require_job_success(result: dict, step: str) -> dict:
    if not isinstance(result, dict):
        raise RuntimeError(f"{step}: unexpected response format: {result!r}")
    if result.get("success") is not True:
        raise RuntimeError(f"{step}: bridge request failed: {json.dumps(result, ensure_ascii=False)}")
    job = result.get("job")
    if not isinstance(job, dict):
        raise RuntimeError(f"{step}: missing job payload: {json.dumps(result, ensure_ascii=False)}")
    if job.get("launchSuccess") is not True:
        raise RuntimeError(f"{step}: remote process failed to launch: {json.dumps(job, ensure_ascii=False)}")
    if job.get("timedOut") is True or result.get("timedOut") is True:
        raise RuntimeError(f"{step}: timed out: {json.dumps(result, ensure_ascii=False)}")
    if int(job.get("exitCode", 1)) != 0:
        raise RuntimeError(f"{step}: remote process exited non-zero: {json.dumps(job, ensure_ascii=False)}")
    return job


def download_file(
    *,
    x64dbg,
    remote_python: str,
    cwd: str,
    source_path: str,
    target_file: Path,
    chunk_size: int,
    timeout_ms: int,
    verify: bool,
) -> dict[str, object]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    stat_result = x64dbg.HostExec(remote_python, build_remote_stat_args(source_path), cwd, timeout_ms)
    stat_job = _require_job_success(stat_result, "stat remote file")
    try:
        metadata = json.loads(stat_job.get("output", "").strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"stat remote file: invalid JSON output: {stat_job.get('output')!r}") from exc

    if metadata.get("exists") is not True:
        raise RuntimeError(f"stat remote file: remote file missing: {json.dumps(metadata, ensure_ascii=False)}")

    remote_size = int(metadata.get("size", 0))
    target_file.parent.mkdir(parents=True, exist_ok=True)

    chunk_results = []
    with target_file.open("wb") as fh:
        for offset in range(0, remote_size, chunk_size):
            read_result = x64dbg.HostExec(
                remote_python,
                build_remote_read_chunk_args(source_path, offset, chunk_size),
                cwd,
                timeout_ms,
            )
            read_job = _require_job_success(read_result, f"read chunk offset={offset}")
            try:
                chunk_payload = json.loads(read_job.get("output", "").strip() or "{}")
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"read chunk offset={offset}: invalid JSON output: {read_job.get('output')!r}") from exc

            actual_offset = int(chunk_payload.get("offset", -1))
            if actual_offset != offset:
                raise RuntimeError(f"read chunk offset mismatch: expected {offset}, got {actual_offset}")
            raw = base64.b64decode(chunk_payload.get("data_b64", ""))
            fh.write(raw)
            chunk_results.append(
                {
                    "offset": offset,
                    "size": len(raw),
                    "jobId": read_job.get("id"),
                    "processId": read_job.get("processId"),
                }
            )

    local_bytes = target_file.read_bytes()
    local_sha256 = hashlib.sha256(local_bytes).hexdigest()
    verification = None
    if verify:
        verification = {
            "exists": True,
            "size": len(local_bytes),
            "sha256": local_sha256,
            "remoteSize": remote_size,
            "remoteSha256": metadata.get("sha256", ""),
        }
        if len(local_bytes) != remote_size:
            raise RuntimeError(f"download verify: size mismatch local={len(local_bytes)} remote={remote_size}")
        if local_sha256 != metadata.get("sha256"):
            raise RuntimeError(
                "download verify: sha256 mismatch "
                f"local={local_sha256} remote={metadata.get('sha256')}"
            )

    return {
        "success": True,
        "sourcePath": source_path,
        "targetFile": str(target_file),
        "chunkCount": len(chunk_results),
        "chunkSize": chunk_size,
        "bytesDownloaded": len(local_bytes),
        "sha256": local_sha256,
        "verified": verify,
        "remoteMetadata": metadata,
        "verification": verification,
        "chunks": chunk_results,
    }


def main() -> None:
    args = parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(args.x64dbg_url)
    result = download_file(
        x64dbg=x64dbg,
        remote_python=args.remote_python,
        cwd=args.cwd,
        source_path=args.source_path,
        target_file=args.target_file,
        chunk_size=args.chunk_size,
        timeout_ms=args.timeout_ms,
        verify=not args.no_verify,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
