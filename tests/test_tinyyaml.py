"""Tests for litaudit.tinyyaml."""

import unittest

from litaudit.tinyyaml import parse, YamlError


class ScalarsTests(unittest.TestCase):
    def test_nested_map(self):
        doc = parse("a:\n  b: 1\n  c: two\n")
        self.assertEqual(doc, {"a": {"b": 1, "c": "two"}})

    def test_quoted_strings(self):
        doc = parse('name: "litellm #1"\ncolor: \'blue\'\n')
        self.assertEqual(doc, {"name": "litellm #1", "color": "blue"})

    def test_comment_stripping(self):
        doc = parse("key: value  # trailing comment\n# whole line\nother: 5\n")
        self.assertEqual(doc, {"key": "value", "other": 5})

    def test_bools_and_null(self):
        doc = parse("on: true\noff: false\nnothing: null\n")
        self.assertEqual(doc, {"on": True, "off": False, "nothing": None})

    def test_inline_list(self):
        doc = parse("models: [a, b, 3]\n")
        self.assertEqual(doc, {"models": ["a", "b", 3]})

    def test_env_ref_string(self):
        doc = parse("api_key: os.environ/OPENAI_API_KEY\n")
        self.assertEqual(doc, {"api_key": "os.environ/OPENAI_API_KEY"})


class ListTests(unittest.TestCase):
    def test_list_of_maps(self):
        text = (
            "model_list:\n"
            "  - model_name: gpt-4o\n"
            "    litellm_params:\n"
            "      model: openai/gpt-4o\n"
            "      api_key: sk-test\n"
            "  - model_name: haiku\n"
            "    litellm_params:\n"
            "      model: anthropic/haiku\n"
        )
        doc = parse(text)
        self.assertEqual(len(doc["model_list"]), 2)
        self.assertEqual(doc["model_list"][0]["model_name"], "gpt-4o")
        self.assertEqual(doc["model_list"][0]["litellm_params"]["api_key"], "sk-test")
        self.assertEqual(doc["model_list"][1]["litellm_params"]["model"], "anthropic/haiku")

    def test_list_at_key_indent(self):
        text = "litellm_settings:\ntelemetry: false\n"
        doc = parse(text)
        self.assertEqual(doc, {"litellm_settings": None, "telemetry": False})

    def test_list_of_scalars(self):
        text = "callbacks:\n  - langfuse\n  - otel\n"
        self.assertEqual(parse(text), {"callbacks": ["langfuse", "otel"]})

    def test_top_level_sequence_rejected(self):
        with self.assertRaises(YamlError):
            parse("- a\n- b\n")


class RobustnessTests(unittest.TestCase):
    def test_empty_document(self):
        self.assertEqual(parse(""), {})

    def test_only_comments(self):
        self.assertEqual(parse("# nothing here\n\n"), {})

    def test_overIndented_noise_never_crashes(self):
        doc = parse("a: 1\n      mystery\nb: 2\n")
        self.assertIn("a", doc)

    def test_inline_empty_map(self):
        self.assertEqual(parse("x: {}\n"), {"x": {}})

    def test_real_shaped_config(self):
        text = (
            "model_list:\n"
            "  - model_name: gpt-4\n"
            "    litellm_params:\n"
            "      model: openai/gpt-4\n"
            "      api_key: os.environ/KEY\n"
            "      max_tokens: 4096\n"
            "general_settings:\n"
            "  master_key: os.environ/MASTER\n"
            "litellm_settings:\n"
            "  telemetry: false\n"
        )
        doc = parse(text)
        self.assertEqual(doc["general_settings"]["master_key"], "os.environ/MASTER")
        self.assertEqual(doc["model_list"][0]["litellm_params"]["max_tokens"], 4096)


if __name__ == "__main__":
    unittest.main()
