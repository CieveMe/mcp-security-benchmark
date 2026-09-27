import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.probes import _classification, load_cases


def _reject_case(case_id):
    return next(case for case in load_cases() if case["id"] == case_id)


class ClassifierTests(unittest.TestCase):
    def test_refusal_in_body_without_is_error_is_a_pass(self):
        """FastMCP returns refusals as ordinary content; the body must be read."""
        case = _reject_case("sql-stacked-statement")
        result = {"content": [{"type": "text", "text": "ERROR: multiple statements are not allowed"}], "isError": False}
        status, detail = _classification(case, result, "ERROR: multiple statements are not allowed", case["arguments"])
        self.assertEqual(status, "pass", detail)

    def test_echoed_dangerous_statement_is_a_failure(self):
        case = _reject_case("sql-stacked-statement")
        text = "executed: SELECT 1; DROP TABLE mcpbench_probe;"
        status, detail = _classification(case, {"content": [{"type": "text", "text": text}]}, text, case["arguments"])
        self.assertEqual(status, "fail", detail)

    def test_is_error_is_still_a_pass(self):
        case = _reject_case("sql-sleep-timeout")
        result = {"isError": True, "content": [{"type": "text", "text": "nope"}]}
        status, _ = _classification(case, result, "nope", case["arguments"])
        self.assertEqual(status, "pass")

    def test_leaked_canary_is_a_failure(self):
        case = next(c for c in load_cases() if c["id"] == "cred-file-outside-sandbox")
        text = "MCPBENCH_CANARY_SECRET=mcpbench-canary-3f9a1c2d7e5b"
        status, detail = _classification(case, {"content": [{"type": "text", "text": text}]}, text, {})
        self.assertEqual(status, "fail", detail)

    def test_unreachable_backend_is_not_a_free_pass(self):
        case = next(c for c in load_cases() if c["id"] == "redact-secret-shaped-output")
        text = "Connection refused while reading from the database"
        result = {"isError": True, "content": [{"type": "text", "text": text}]}
        status, detail = _classification(case, result, text, {})
        self.assertEqual(status, "not_applicable", detail)

    def test_case_corpus_is_well_formed(self):
        for case in load_cases():
            self.assertIn("severity", case)
            self.assertIn(case["severity"], {"critical", "high", "medium", "low"})
            self.assertTrue(case.get("expect") or case.get("mode"), case["id"])


if __name__ == "__main__":
    unittest.main()
