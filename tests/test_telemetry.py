import json
import tempfile
import unittest
from pathlib import Path
from soclab.telemetry import AuditSink, load_events, parse_timestamp


class TelemetryTests(unittest.TestCase):
    def test_round_trip(self):
        sink = AuditSink()
        sink.record(event_type="auth", src_ip="127.0.0.2", service="lab", result="denied", principal="alice")
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "events.jsonl"
            sink.save(file)
            out = load_events(file)
            self.assertEqual(out[0]["principal"], "alice")
            self.assertEqual(out[0]["event_id"], "evt-00001")

    def test_empty_file_is_allowed(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "empty.jsonl"
            p.write_text("", encoding="utf-8")
            self.assertEqual(load_events(p), [])

    def test_missing_timestamp_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "broken.jsonl"
            p.write_text(json.dumps({"event_id": "e", "event_type": "auth"}) + "\n")
            with self.assertRaisesRegex(ValueError, "missing required"):
                load_events(p)

    def test_naive_datetime_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            parse_timestamp("2026-11-20T10:30:00")

    def test_oversized_event_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "over.jsonl"
            p.write_bytes(b"a" * 66000 + b"\n")
            with self.assertRaisesRegex(ValueError, "too large"):
                load_events(p)

    def test_invalid_auth_record_rejected(self):
        sink = AuditSink()
        with self.assertRaises(ValueError):
            sink.record(event_type="not-real", src_ip="127.0.0.1", service="bad", result="bad")


if __name__ == "__main__":
    unittest.main()
