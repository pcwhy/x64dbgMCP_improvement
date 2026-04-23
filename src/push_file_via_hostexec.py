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
        description="Upload a local file to a Windows VM path through x64dbg HostExec and remote Python.",
    )
    parser.add_argument("--x64dbg-url", required=True, help="x64dbg HTTP bridge URL")
    parser.add_argument("--remote-python", required=True, help="Remote Python executable path on the Windows VM")
    parser.add_argument("--cwd", default="", help="Optional remote working directory")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Raw bytes per uploaded chunk")
    parser.add_argument("--timeout-ms", type=int, default=30000, help="Per-chunk HostExec timeout")
    parser.add_argument("--no-verify", action="store_true", help="Skip remote size/hash verification at the end")
    parser.add_argument("source_file", type=Path, help="Local source file to upload")
    parser.add_argument("target_path", help="Remote destination file path on the Windows VM")
    return parser.parse_args()


def chunk_bytes(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def _b64_text(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_remote_write_args(target_path: str, chunk: bytes, *, append: bool) -> str:
    path_b64 = _b64_text(target_path.encode("utf-8"))
    chunk_b64 = _b64_text(chunk)
    mode = "ab" if append else "wb"
    code = (
        "import base64,pathlib;"
        f"p=pathlib.Path(base64.b64decode('{path_b64}').decode('utf-8'));"
        "p.parent.mkdir(parents=True, exist_ok=True);"
        f"fh=open(p,'{mode}');"
        f"fh.write(base64.b64decode('{chunk_b64}'));"
        "fh.close()"
    )
    return f'-c "{code}"'


def build_remote_verify_args(target_path: str) -> str:
    path_b64 = _b64_text(target_path.encode("utf-8"))
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


def upload_file(
    *,
    x64dbg,
    remote_python: str,
    cwd: str,
    source_file: Path,
    target_path: str,
    chunk_size: int,
    timeout_ms: int,
    verify: bool,
) -> dict[str, object]:
    payload = source_file.read_bytes()
    chunks = chunk_bytes(payload, chunk_size) or [b""]
    chunk_results = []
    for index, chunk in enumerate(chunks):
        args = build_remote_write_args(target_path, chunk, append=index > 0)
        result = x64dbg.HostExec(remote_python, args, cwd, timeout_ms)
        job = _require_job_success(result, f"upload chunk {index + 1}/{len(chunks)}")
        chunk_results.append(
            {
                "index": index,
                "size": len(chunk),
                "jobId": job.get("id"),
                "processId": job.get("processId"),
            }
        )

    verification = None
    local_sha256 = hashlib.sha256(payload).hexdigest()
    if verify:
        verify_args = build_remote_verify_args(target_path)
        verify_result = x64dbg.HostExec(remote_python, verify_args, cwd, timeout_ms)
        verify_job = _require_job_success(verify_result, "verify upload")
        try:
            verification = json.loads(verify_job.get("output", "").strip() or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"verify upload: invalid JSON output: {verify_job.get('output')!r}") from exc
        if verification.get("exists") is not True:
            raise RuntimeError(f"verify upload: remote file missing: {json.dumps(verification, ensure_ascii=False)}")
        if int(verification.get("size", -1)) != len(payload):
            raise RuntimeError(
                f"verify upload: size mismatch local={len(payload)} remote={verification.get('size')}"
            )
        if verification.get("sha256") != local_sha256:
            raise RuntimeError(
                "verify upload: sha256 mismatch "
                f"local={local_sha256} remote={verification.get('sha256')}"
            )

    return {
        "success": True,
        "sourceFile": str(source_file),
        "targetPath": target_path,
        "chunkCount": len(chunks),
        "chunkSize": chunk_size,
        "bytesUploaded": len(payload),
        "sha256": local_sha256,
        "verified": verify,
        "verification": verification,
        "chunks": chunk_results,
    }


def main() -> None:
    args = parse_args()
    if not args.source_file.exists():
        raise SystemExit(f"Local source file does not exist: {args.source_file}")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import x64dbg  # noqa: PLC0415

    x64dbg.set_x64dbg_server_url(args.x64dbg_url)
    result = upload_file(
        x64dbg=x64dbg,
        remote_python=args.remote_python,
        cwd=args.cwd,
        source_file=args.source_file,
        target_path=args.target_path,
        chunk_size=args.chunk_size,
        timeout_ms=args.timeout_ms,
        verify=not args.no_verify,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
