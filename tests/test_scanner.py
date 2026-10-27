"""Tests for litaudit.scanner — every rule must fire and the clean config
must stay quiet."""

import json
import os
import tempfile
import unittest

from litaudit.cli import main
from litaudit.scanner import scan_config

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(os.path.dirname(HERE), "examples")
DANGEROUS = os.path.join(EXAMPLES, "dangerous_config.yaml")
CLEAN = os.path.join(EXAMPLES, "clean_config.yaml")


def scan_temp(content: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(content)
        path = fh.name
    try:
        return scan_config(path)
    finally:
        os.unlink(path)


def rules(result_or_content):
    if isinstance(result_or_content, str):
        result = scan_temp(result_or_content)
    else:
        result = result_or_content
    return [f.rule for f in result["findings"]]


class RuleFiresTests(unittest.TestCase):
    def test_lit001_live_master_key_literal(self):
        r = scan_temp("general_settings:\n  master_key: sk-AbCdEf1234567890AbCdEf1234567890\n")
        self.assertIn("LIT-001", rules(r))
        self.assertEqual(r["findings"][0].severity, "critical")

    def test_lit001_placeholder_master_key(self):
        r = scan_temp("general_settings:\n  master_key: changeme\n")
        self.assertIn("LIT-001", rules(r))

    def test_lit001_short_master_key(self):
        r = scan_temp("general_settings:\n  master_key: abc123xyz\n")
        self.assertIn("LIT-001", rules(r))

    def test_lit002_provider_key_literal(self):
        r = scan_temp(
            "model_list:\n"
            "  - model_name: gpt-4o\n"
            "    litellm_params:\n"
            "      model: openai/gpt-4o\n"
            "      api_key: sk-AbCdEf1234567890AbCdEf1234567890\n")
        fired = [f for f in r["findings"] if f.rule == "LIT-002"]
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].severity, "critical")

    def test_lit003_db_url_credentials(self):
        r = scan_temp("general_settings:\n  database_url: postgres://u:hunter2@db:5432/x\n")
        self.assertIn("LIT-003", rules(r))

    def test_lit004_plaintext_env_secret(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "general_settings:\n  master_key: os.environ/MK\n"
            "litellm_settings:\n  telemetry: false\n  max_budget: 10\n"
            "environment_variables:\n"
            "  ANTHROPIC_API_KEY: sk-ant-api03-XyZ1234567890abcdefghij\n")
        r = scan_temp(body)
        self.assertIn("LIT-004", rules(r))

    def test_lit005_plaintext_endpoint(self):
        r = scan_temp(
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "      api_base: http://inference.example.com:8000\n")
        self.assertIn("LIT-005", rules(r))

    def test_lit006_missing_master_key(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "      rpm: 10\n")
        r = scan_temp(body)
        self.assertIn("LIT-006", rules(r))

    def test_lit007_wildcard_model(self):
        r = scan_temp(
            "model_list:\n  - model_name: \"*\"\n    litellm_params:\n"
            "      model: openai/*\n      api_key: os.environ/K\n")
        self.assertIn("LIT-007", rules(r))

    def test_lit008_no_spend_controls(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "general_settings:\n  master_key: os.environ/MK\n"
            "litellm_settings:\n  telemetry: false\n")
        self.assertIn("LIT-008", rules(body))

    def test_lit009_telemetry_enabled_by_default(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "      rpm: 10\n"
            "general_settings:\n  master_key: os.environ/MK\n")
        self.assertIn("LIT-009", rules(body))

    def test_lit010_remote_callback(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "      rpm: 10\n"
            "general_settings:\n  master_key: os.environ/MK\n"
            "litellm_settings:\n  telemetry: false\n"
            "callbacks:\n"
            "  success_handler: https://logs.mysite.dev/collect\n")
        self.assertIn("LIT-010", rules(body))

    def test_lit011_weak_credential_value(self):
        body = (
            "model_list:\n  - model_name: m\n    litellm_params:\n"
            "      model: openai/m\n      api_key: os.environ/K\n"
            "      rpm: 10\n"
            "general_settings:\n  master_key: os.environ/MK\n"
            "litellm_settings:\n  telemetry: false\n"
            "slack_callback:\n  api_token: changeme\n")
        self.assertIn("LIT-011", rules(body))


class CleanConfigTests(unittest.TestCase):
    def test_example_clean_config_passes(self):
        result = scan_config(CLEAN)
        self.assertEqual(result["error"], None)
        self.assertEqual(result["findings"], [], msg=str(result["findings"]))

    def test_example_dangerous_config_hits(self):
        result = scan_config(DANGEROUS)
        got = set(rules(result))
        want = {"LIT-001", "LIT-002", "LIT-003", "LIT-004", "LIT-005",
                "LIT-007", "LIT-008", "LIT-009", "LIT-010"}
        self.assertTrue(want.issubset(got), msg=f"missing: {want - got}")
        critical = [f for f in result["findings"] if f.severity == "critical"]
        self.assertGreaterEqual(len(critical), 3)

    def test_missing_file_is_an_error(self):
        result = scan_config("/nonexistent/config.yaml")
        self.assertNotEqual(result["error"], None)


class CliTests(unittest.TestCase):
    def test_exit_0_on_clean(self):
        self.assertEqual(main([CLEAN]), 0)

    def test_exit_1_on_dangerous(self):
        self.assertEqual(main([DANGEROUS]), 1)

    def test_exit_1_quiet_mode(self):
        self.assertEqual(main([DANGEROUS, "--quiet"]), 1)

    def test_high_threshold_still_fails_on_dangerous(self):
        self.assertEqual(main([DANGEROUS, "--fail-on", "critical"]), 1)

    def test_exit_2_on_unreadable(self):
        self.assertEqual(main(["/nonexistent/config.yaml"]), 2)

    def test_json_output_parses(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([DANGEROUS, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data["files"]), 1)
        self.assertTrue(data["files"][0]["findings"])

    def test_fail_on_low_fails_on_cleanish(self):
        # clean config has zero findings; low threshold still exits 0
        self.assertEqual(main([CLEAN, "--fail-on", "low"]), 0)

    def test_version_flag(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["--version"]), 0)
        self.assertIn("1.0.0", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
