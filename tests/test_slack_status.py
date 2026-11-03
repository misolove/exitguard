"""Read-only Slack metadata; no network calls or real credentials."""
import json
import unittest
from unittest.mock import mock_open, patch
from test_dash_layout import load_dash


class SlackStatusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load_dash()

    def status(self, notify):
        with patch.object(self.d.core, "DEMO", False), patch(
                "builtins.open", mock_open(read_data=json.dumps({"notify": notify}))):
            return self.d.slack_status()

    def test_demo_does_not_read_configuration(self):
        with patch.object(self.d.core, "DEMO", True), patch("builtins.open") as opened:
            self.assertEqual(self.d.slack_status()["state"], "demo")
            opened.assert_not_called()

    def test_only_safe_metadata_leaves_server(self):
        # Deliberately synthetic URL, never a live credential.
        url = "https://hooks.slack.com/services/fake/test/not-a-secret"
        result = self.status({"webhook_url": url, "min_level": "HIGH"})
        self.assertEqual(result, {"state": "configured", "min_level": "HIGH"})
        self.assertNotIn(url, json.dumps(result))

    def test_other_missing_and_invalid_config(self):
        self.assertEqual(self.status({})["state"], "missing")
        self.assertEqual(self.status({"webhook_url": "https://example.invalid"})["state"], "other")
        self.assertEqual(self.status({"webhook_url": "https://hooks.slack.com.example.invalid/services/test"})["state"], "other")
        self.assertEqual(self.status({"min_level": "secret-like-value"})["min_level"], "UNKNOWN")
        with patch.object(self.d.core, "DEMO", False), patch("builtins.open", side_effect=PermissionError):
            self.assertEqual(self.d.slack_status()["state"], "unknown")
