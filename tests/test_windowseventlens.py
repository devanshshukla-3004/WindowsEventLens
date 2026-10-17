import unittest

from windowseventlens import analyze, normalize


class WindowsEventLensTests(unittest.TestCase):
    def test_normalizes_windows_field_names(self):
        event = normalize({"EventID": 4625, "TargetUserName": "alice", "IpAddress": "10.0.0.8"})
        self.assertEqual(event["event_id"], 4625)
        self.assertEqual(event["target_user"], "alice")

    def test_below_threshold_no_failed_login_finding(self):
        report = analyze([{"event_id": 4625, "ip_address": "10.0.0.1"} for _ in range(4)], 5)
        self.assertEqual(report["summary"]["findings"], 0)

    def test_source_burst_detected(self):
        report = analyze([{"event_id": 4625, "ip_address": "10.0.0.8", "target_user": "a"} for _ in range(5)], 5)
        self.assertIn("WEL-001", [finding["rule_id"] for finding in report["findings"]])

    def test_user_target_burst_detected(self):
        report = analyze([{"event_id": 4625, "ip_address": f"10.0.0.{i}", "target_user": "admin"} for i in range(1, 6)], 5)
        self.assertIn("WEL-002", [finding["rule_id"] for finding in report["findings"]])

    def test_log_cleared_high_severity(self):
        report = analyze([{"event_id": 1102, "computer": "LAB-PC", "timestamp": "2026-10-17T10:00:00Z"}])
        self.assertEqual(report["findings"][0]["severity"], "HIGH")

    def test_account_creation_flagged(self):
        report = analyze([{"event_id": 4720, "target_user": "newuser"}])
        self.assertIn("WEL-004", [finding["rule_id"] for finding in report["findings"]])

    def test_empty_input(self):
        report = analyze([])
        self.assertEqual(report["summary"]["total_events"], 0)
        self.assertEqual(report["summary"]["average_finding_score"], 0)

    def test_unknown_event_is_preserved(self):
        report = analyze([{"event_id": 9999}])
        self.assertEqual(report["events"][0]["event_id"], 9999)


if __name__ == "__main__":
    unittest.main()
