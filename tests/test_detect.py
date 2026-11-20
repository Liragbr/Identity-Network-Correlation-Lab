"""Behavioral tests with deterministic timestamps; not a production accuracy claim."""
import unittest
from datetime import datetime, timedelta, timezone

from soclab.detect import correlate

BASE = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def ev(index, *, source="127.0.0.2", principal="lab.user01", result="denied",
       kind="auth", seconds=0, qname=None, port=None):
    item = {"event_id": f"e-{index:03d}", "timestamp": (BASE + timedelta(seconds=seconds)).isoformat(),
            "event_type": kind, "src_ip": source, "dst_ip": "127.0.0.1", "service": "test",
            "result": result}
    if kind == "auth":
        item["principal"] = principal
    if kind == "dns_ptr":
        item["qname"] = qname or f"{index}.2.0.192.in-addr.arpa."
    if kind == "tcp_connection":
        item["dst_port"] = port or 4000 + index
    return item


class DetectionTests(unittest.TestCase):
    def test_minimum_distinct_users(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(6)]
        finding = correlate(data)["findings"]
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0]["category"], "password_spray_pattern")
        self.assertEqual(finding[0]["distinct_values"], 6)

    def test_less_than_threshold_not_detected(self):
        data = [ev(i, principal=f"lab.user{i:02}") for i in range(5)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_single_account_retries_not_spray(self):
        data = [ev(i, principal="lab.service") for i in range(35)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_multiple_sources_must_not_be_merged(self):
        data = [ev(i, source="127.0.0.2" if i < 3 else "127.0.0.3",
                   principal=f"lab.user{i:02}") for i in range(6)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_sliding_window_expires_old_events(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i*35) for i in range(8)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_sliding_window_detects_cross_boundary(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=20+i*18) for i in range(6)]
        self.assertEqual(len(correlate(data)["findings"]), 1)

    def test_120_seconds_inclusive(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i*24) for i in range(6)]
        self.assertEqual(len(correlate(data)["findings"]), 1)

    def test_121_seconds_excluded(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i*25) for i in range(6)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_order_does_not_change_findings(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(7)]
        self.assertEqual(correlate(data)["findings"], correlate(list(reversed(data)))["findings"])

    def test_success_elsewhere_not_attributed(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(7)]
        data.append(ev(100, source="127.0.0.3", principal="lab.user04", result="success", seconds=10))
        self.assertEqual(correlate(data)["findings"][0]["successful_auth_from_same_origin_in_window"], 0)

    def test_success_same_origin_is_not_claimed_compromise(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(7)]
        data.append(ev(100, principal="lab.user04", result="success", seconds=10))
        finding = correlate(data)["findings"][0]
        self.assertEqual(finding["successful_auth_from_same_origin_in_window"], 1)
        self.assertIn("NOT established", finding["conclusion"])

    def test_success_outside_window_is_not_linked(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(7)]
        data.append(ev(100, result="success", seconds=300))
        self.assertEqual(correlate(data)["findings"][0]["successful_auth_from_same_origin_in_window"], 0)

    def test_dns_unique_targets(self):
        data = [ev(i, kind="dns_ptr", result="answered", qname="1.2.0.192.in-addr.arpa.") for i in range(12)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_dns_five_names_detected(self):
        data = [ev(i, kind="dns_ptr", result="answered") for i in range(5)]
        self.assertEqual(correlate(data)["findings"][0]["category"], "reverse_dns_discovery")

    def test_three_ports_detected(self):
        data = [ev(i, kind="tcp_connection", result="accepted", port=10000+i) for i in range(3)]
        self.assertEqual(correlate(data)["findings"][0]["category"], "service_connectivity_sweep")

    def test_duplicate_port_does_not_count_as_new(self):
        data = [ev(i, kind="tcp_connection", result="accepted", port=10001) for i in range(10)]
        self.assertEqual(correlate(data)["findings"], [])

    def test_denied_is_not_counted_as_success(self):
        data = [ev(i, principal=f"lab.user{i:02}", seconds=i) for i in range(6)]
        self.assertEqual(correlate(data)["findings"][0]["successful_auth_from_same_origin_in_window"], 0)

    def test_reject_invalid_rule_configuration(self):
        with self.assertRaises(ValueError):
            correlate([], {"distinct_accounts": 0})
        with self.assertRaises(ValueError):
            correlate([], {"window_seconds": 9999999})

    def test_metadata_not_claimed_as_production(self):
        report = correlate([])
        self.assertEqual(report["metadata"]["dataset_kind"], "real_loopback_lab_traffic")
        self.assertIn("not proof", report["metadata"]["claims"])


if __name__ == "__main__":
    unittest.main()

class CompoundCorrelationTests(unittest.TestCase):
    def test_three_signals_same_origin_and_time(self):
        events = [ev(i, principal=f"user{i}", seconds=i) for i in range(6)]
        events += [ev(100+i, kind="dns_ptr", result="answered", seconds=10+i) for i in range(5)]
        events += [ev(200+i, kind="tcp_connection", result="accepted", seconds=30+i) for i in range(3)]
        result = correlate(events)
        self.assertEqual(len(result["correlations"]), 1)
        self.assertEqual(len(result["correlations"][0]["evidence_ids"]), 14)

    def test_three_signals_on_different_sources_dont_correlate(self):
        events = [ev(i, principal=f"user{i}", seconds=i, source="127.0.0.2") for i in range(6)]
        events += [ev(100+i, kind="dns_ptr", result="answered", seconds=10+i, source="127.0.0.3") for i in range(5)]
        events += [ev(200+i, kind="tcp_connection", result="accepted", seconds=30+i, source="127.0.0.4") for i in range(3)]
        self.assertEqual(correlate(events)["correlations"], [])

    def test_signals_far_apart_dont_correlate(self):
        events = [ev(i, principal=f"user{i}", seconds=i) for i in range(6)]
        events += [ev(100+i, kind="dns_ptr", result="answered", seconds=150+i) for i in range(5)]
        events += [ev(200+i, kind="tcp_connection", result="accepted", seconds=300+i) for i in range(3)]
        self.assertEqual(correlate(events)["correlations"], [])
