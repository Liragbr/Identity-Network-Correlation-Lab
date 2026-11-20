"""Thread-safe JSONL audit sink and strict local event parser."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_KINDS = frozenset({"auth", "dns_ptr", "tcp_connection"})
REQUIRED = {"event_id", "timestamp", "event_type", "src_ip", "dst_ip", "service", "result"}
MAX_LINE_BYTES = 64 * 1024


class AuditSink:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []

    def record(self, *, event_type: str, src_ip: str, service: str, result: str,
               dst_ip: str = "127.0.0.1", **fields: Any) -> None:
        if event_type not in ALLOWED_KINDS:
            raise ValueError(f"unsupported event type: {event_type}")
        with self._lock:
            event: dict[str, Any] = {
                "event_id": f"evt-{len(self._events) + 1:05d}",
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "event_type": event_type, "src_ip": src_ip, "dst_ip": dst_ip,
                "service": service, "result": result,
            }
            event.update(fields)
            self._events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [ev.copy() for ev in self._events]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for event in self.snapshot():
                f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("rb") as f:
        for number, raw in enumerate(f, 1):
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"line {number}: event too large")
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"line {number}: malformed JSON") from exc
            if not isinstance(event, dict) or not REQUIRED.issubset(event):
                raise ValueError(f"line {number}: missing required fields")
            if event["event_type"] not in ALLOWED_KINDS:
                raise ValueError(f"line {number}: unsupported event type")
            if any(not isinstance(event[k], str) or not event[k] for k in REQUIRED):
                raise ValueError(f"line {number}: required fields must be nonempty strings")
            parse_timestamp(event["timestamp"])
            if event["event_type"] == "auth" and not isinstance(event.get("principal"), str):
                raise ValueError(f"line {number}: auth principal missing")
            if event["event_type"] == "dns_ptr" and not isinstance(event.get("qname"), str):
                raise ValueError(f"line {number}: DNS qname missing")
            if event["event_type"] == "tcp_connection" and not isinstance(event.get("dst_port"), int):
                raise ValueError(f"line {number}: TCP dst_port missing")
            events.append(event)
    return events
