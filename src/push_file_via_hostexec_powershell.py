#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from x64dbg_tools.file_transfer_core import (
    b64_text,
    chunk_bytes,
    require_existing_remote_file,
    require_size_and_sha256_match,
    sha256_hex,
)
from x64dbg_tools.hostexec_config import add_hostexec_common_arguments, add_remote_powershell_argument
from x64dbg_tools.hostexec_jobs import require_job_success
from x64dbg_tools.url_config import add_x64dbg_url_argument


DEFAULT_CHUNK_SIZE = 3072


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload a local file to a Windows VM path through x64dbg HostExec and remote PowerShell/.NET.",
    )
    add_x64dbg_url_argument(parser)
    add_remote_powershell_argument(parser)
    add_hostexec_common_arguments(parser)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Raw bytes per uploaded chunk")
    parser.add_argument("--no-verify", action="store_true", help="Skip remote size/hash verification at the end")
    parser.add_argument("source_file", type=Path, help="Local source file to upload")
    parser.add_argument("target_path", help="Remote destination file path on the Windows VM")
    return parser.parse_args()
def _powershell_command(script: str) -> str:
    return f'-NoProfile -NonInteractive -Command "{script}"'


def build_remote_write_args(target_path: str, chunk: bytes, *, append: bool) -> str:
    path_b64 = b64_text(target_path.encode("utf-8"))
    chunk_b64 = b64_text(chunk)
    if append:
        write_expr = (
            "$fs=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None);"
            "$fs.Write($bytes,0,$bytes.Length);"
            "$fs.Close();"
        )
    else:
        write_expr = "[IO.File]::WriteAllBytes($path,$bytes);"
    script = (
        "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String"
        f"('{path_b64}'));"
        "$bytes=[Convert]::FromBase64String"
        f"('{chunk_b64}');"
        "[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null;"
        f"{write_expr}"
    )
    return _powershell_command(script)


def build_remote_verify_args(target_path: str) -> str:
    path_b64 = b64_text(target_path.encode("utf-8"))
    script = (
        "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String"
        f"('{path_b64}'));"
        "if (-not (Test-Path $path)) {"
        "Write-Output ('0' + [char]9 + '0' + [char]9);"
        "exit 0"
        "};"
        "$bytes=[IO.File]::ReadAllBytes($path);"
        "$sha=[System.Security.Cryptography.SHA256Managed]::Create();"
        "$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLower();"
        "Write-Output ('1' + [char]9 + [string]$bytes.Length + [char]9 + $hash)"
    )
    return _powershell_command(script)


def parse_remote_verify_output(output: str) -> dict[str, object]:
    parts = output.strip().split("\t")
    if len(parts) != 3:
        raise RuntimeError(f"verify upload: invalid verification output: {output!r}")
    exists_flag, size_text, sha256 = parts
    return {
        "exists": exists_flag == "1",
        "size": int(size_text),
        "sha256": sha256,
    }


def upload_file(
    *,
    x64dbg,
    remote_powershell: str,
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
        result = x64dbg.HostExec(remote_powershell, args, cwd, timeout_ms)
        job = require_job_success(result, f"upload chunk {index + 1}/{len(chunks)}")
        chunk_results.append(
            {
                "index": index,
                "size": len(chunk),
                "jobId": job.get("id"),
                "processId": job.get("processId"),
            }
        )

    verification = None
    local_sha256 = sha256_hex(payload)
    if verify:
        verify_args = build_remote_verify_args(target_path)
        verify_result = x64dbg.HostExec(remote_powershell, verify_args, cwd, timeout_ms)
        verify_job = require_job_success(verify_result, "verify upload")
        verification = parse_remote_verify_output(verify_job.get("output", ""))
        require_existing_remote_file(verification, step="verify upload")
        require_size_and_sha256_match(
            local_size=len(payload),
            local_sha256=local_sha256,
            remote_size=int(verification.get("size", -1)),
            remote_sha256=str(verification.get("sha256", "")),
            step="verify upload",
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

    x64dbg.set_x64dbg_server_url(args.url)
    result = upload_file(
        x64dbg=x64dbg,
        remote_powershell=args.remote_powershell,
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
