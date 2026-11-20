import tempfile
import unittest
from pathlib import Path
from soclab.lab import run_local_experiment
from soclab.detect import correlate
from soclab.telemetry import load_events
from soclab.report import write_report


class LiveIntegrationTests(unittest.TestCase):
    def test_end_to_end_real_loopback(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            output = base / "events.jsonl"
            produced = run_local_experiment(output)
            loaded = load_events(output)
            self.assertEqual(len(loaded), 31)
            self.assertEqual(produced, loaded)
            self.assertEqual(set(e["src_ip"] for e in loaded), {"127.0.0.2", "127.0.0.3", "127.0.0.4"})
            result = correlate(loaded)
            self.assertEqual(len(result["findings"]), 3)
            self.assertEqual(len(result["correlations"]), 1)
            self.assertEqual({f["src_ip"] for f in result["findings"]}, {"127.0.0.2"})
            for finding in result["findings"]:
                self.assertEqual(finding["successful_auth_from_same_origin_in_window"], 0)
            findings_before = correlate(loaded)
            self.assertEqual(findings_before, correlate(load_events(output)))
            write_report(loaded, result, base / "report")
            text = (base / "report" / "case-report.md").read_text(encoding="utf-8")
            self.assertIn("não", text.lower())
            self.assertIn("31", text)
            self.assertTrue((base / "report" / "timeline.csv").exists())
            # Real credentials may be in client test source, NEVER in audit artifacts.
            self.assertNotIn("LabWrong!2026", output.read_text())
            self.assertNotIn("LocalDemo!2026", output.read_text())
            self.assertNotIn("BadServicePassword", output.read_text())


if __name__ == "__main__":
    unittest.main()
