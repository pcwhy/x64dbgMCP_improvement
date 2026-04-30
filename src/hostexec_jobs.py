#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any


def require_job_success(result: Any, step: str) -> dict:
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
