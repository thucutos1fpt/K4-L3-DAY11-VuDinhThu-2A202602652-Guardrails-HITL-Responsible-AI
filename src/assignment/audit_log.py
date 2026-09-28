"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store an input and its monotonic start time; return its request ID."""
        request_id = request_id or f"{user_id}-{len(self.logs) + len(self._open) + 1}"
        self._open[request_id] = {
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }
        return request_id
    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Close a request, calculate latency, and append a forensic record."""
        request_id = request_id or f"{user_id}-unmatched-{len(self.logs) + 1}"
        started = self._open.pop(request_id, None)
        started_perf = started.get("started_perf") if started else None
        latency_ms = (
            round((time.perf_counter() - started_perf) * 1000, 2)
            if started_perf is not None
            else None
        )
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input": started.get("input") if started else None,
            "started_at": started.get("started_at") if started else None,
            "completed_at": utc_now_iso(),
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry
    def export_json(self, filepath: str | None = None):
        """Write completed audit records as a JSON array."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
