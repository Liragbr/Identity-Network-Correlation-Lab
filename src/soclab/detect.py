"""Sliding-window defensive correlations. No assertion of account compromise."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Any, Callable

from .telemetry import parse_timestamp

DEFAULTS = {"window_seconds": 120, "distinct_accounts": 6,
            "ptr_distinct": 5, "service_distinct": 3}


def _clusters(events: list[dict[str, Any]], field: str, threshold: int,
              window_seconds: int, predicate: Callable[[dict[str, Any]], bool],
              category: str, mitre: str) -> list[dict[str, Any]]:
    """True sliding windows; one maximal finding per origin, no double counting."""
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if predicate(event):
            by_source[event["src_ip"]].append(event)
    findings: list[dict[str, Any]] = []
    for src, items in sorted(by_source.items()):
        items.sort(key=lambda e: (parse_timestamp(e["timestamp"]), e["event_id"]))
        window: deque[dict[str, Any]] = deque()
        frequencies: Counter[Any] = Counter()
        best: tuple[int, int, list[dict[str, Any]]] | None = None
        for event in items:
            t = parse_timestamp(event["timestamp"])
            window.append(event)
            frequencies[event[field]] += 1
            while window and t - parse_timestamp(window[0]["timestamp"]) > timedelta(seconds=window_seconds):
                old = window.popleft()
                frequencies[old[field]] -= 1
                if frequencies[old[field]] == 0:
                    del frequencies[old[field]]
            score = (len(frequencies), len(window))
            if score[0] >= threshold and (best is None or score > best[:2]):
                best = (*score, list(window))
        if best:
            selected = best[2]
            findings.append({
                "category": category, "src_ip": src, "mitre_technique": mitre,
                "first_seen": selected[0]["timestamp"], "last_seen": selected[-1]["timestamp"],
                "event_count": len(selected), "distinct_values": len({e[field] for e in selected}),
                "evidence_ids": [e["event_id"] for e in selected],
            })
    return findings


def correlate(events: list[dict[str, Any]], config: dict[str, int] | None = None) -> dict[str, Any]:
    cfg = {**DEFAULTS, **(config or {})}
    if not 1 <= cfg["window_seconds"] <= 86400 or any(cfg[key] < 2 for key in ("distinct_accounts", "ptr_distinct", "service_distinct")):
        raise ValueError("invalid detection thresholds")
    auth_failed = lambda e: e["event_type"] == "auth" and e["result"] == "denied"
    ptr = lambda e: e["event_type"] == "dns_ptr" and e["result"] == "answered"
    tcp = lambda e: e["event_type"] == "tcp_connection" and e["result"] == "accepted"
    findings = (
        _clusters(events, "principal", cfg["distinct_accounts"], cfg["window_seconds"], auth_failed,
                  "password_spray_pattern", "T1110.003") +
        _clusters(events, "qname", cfg["ptr_distinct"], cfg["window_seconds"], ptr,
                  "reverse_dns_discovery", "T1018") +
        _clusters(events, "dst_port", cfg["service_distinct"], cfg["window_seconds"], tcp,
                  "service_connectivity_sweep", "T1046")
    )
    successes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "auth" and e["result"] == "success":
            successes[e["src_ip"]].append(e)
    for finding in findings:
        src = finding["src_ip"]
        ftime = parse_timestamp(finding["first_seen"])
        last = parse_timestamp(finding["last_seen"])
        same_origin = [e for e in successes[src] if
                       ftime <= parse_timestamp(e["timestamp"]) <= last + timedelta(seconds=cfg["window_seconds"])]
        finding["successful_auth_from_same_origin_in_window"] = len(same_origin)
        finding["conclusion"] = (
            "Valid authentication observed from the same origin; authorization and compromise are NOT established."
            if same_origin else
            "Suspicious behavior observed; successful unauthorized access is NOT established."
        )
    findings.sort(key=lambda f: (f["src_ip"], f["category"]))
    # Second-stage cross-signal correlation: source match AND temporal proximity.
    by_source_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_source_findings[finding["src_ip"]].append(finding)
    compound: list[dict[str, Any]] = []
    required = {"password_spray_pattern", "reverse_dns_discovery", "service_connectivity_sweep"}
    for src, hits in sorted(by_source_findings.items()):
        selected = [f for f in hits if f["category"] in required]
        if {f["category"] for f in selected} != required:
            continue
        earliest = min(parse_timestamp(f["first_seen"]) for f in selected)
        latest = max(parse_timestamp(f["last_seen"]) for f in selected)
        if latest - earliest > timedelta(seconds=cfg["window_seconds"]):
            continue
        matched_ids = sorted({event_id for f in selected for event_id in f["evidence_ids"]})
        compound.append({
            "src_ip": src, "category": "multi_signal_auth_and_discovery",
            "signal_categories": sorted(required),
            "first_seen": earliest.isoformat().replace("+00:00", "Z"),
            "last_seen": latest.isoformat().replace("+00:00", "Z"),
            "evidence_ids": matched_ids,
            "assessment": "Correlated suspicious activity; identity compromise and lateral movement remain unproven.",
        })
    return {
        "metadata": {"dataset_kind": "real_loopback_lab_traffic", "rules": cfg,
                     "claims": "Detection signals only; not proof of compromise or lateral movement."},
        "observed_events": len(events),
        "sources": dict(sorted(Counter(e["src_ip"] for e in events).items())),
        "findings": findings,
        "correlations": compound,
    }
