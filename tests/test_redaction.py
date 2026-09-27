import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.probes import _excerpt, redact
from bench.targets import expand


class RedactionTests(unittest.TestCase):
    def test_absolute_paths_are_masked(self):
        text = r'{"ANDROID_HOME": "D:\develop\Android\Sdk", "config": "/home/ci/.aws/credentials"}'
        cleaned = redact(text)
        self.assertNotIn("D:\\develop", cleaned)
        self.assertNotIn("/home/ci", cleaned)
        self.assertIn("<path>", cleaned)

    def test_secret_shaped_values_are_masked(self):
        cleaned = redact("API_KEY=abcdef123456 token: ghp_verysecretvalue")
        self.assertNotIn("abcdef123456", cleaned)
        self.assertNotIn("ghp_verysecretvalue", cleaned)

    def test_excerpt_keeps_only_the_evidence_lines(self):
        text = '\n'.join([
            '"ALLUSERSPROFILE": "C:\\\\ProgramData",',
            '"ANDROID_HOME": "D:\\\\develop\\\\Android\\\\Sdk",',
            '"MCPBENCH_CANARY_SECRET": "mcpbench-canary-3f9a1c2d7e5b",',
            '"MCPBENCH_CANARY_TOKEN": "sk-mcpbench-canary-0000deadbeef1111",',
        ])
        excerpt = _excerpt(text, ["mcpbench-canary-3f9a1c2d7e5b"])
        self.assertIn("mcpbench-canary-3f9a1c2d7e5b", excerpt)
        self.assertNotIn("ProgramData", excerpt)
        self.assertNotIn("ANDROID_HOME", excerpt)

    def test_target_placeholders_do_not_leak_absolute_paths(self):
        self.assertEqual(Path(expand("{root}/.npm-cache")), ROOT / ".npm-cache")
        self.assertEqual(
            Path(expand("{env:MCPBENCH_DOES_NOT_EXIST:{root}/third_party/x}")),
            ROOT / "third_party" / "x",
        )
        self.assertEqual(
            Path(expand("{env:MCPBENCH_ALLOWED_DIR:{root}/third_party/x}")),
            ROOT / "third_party" / "x",
        )


if __name__ == "__main__":
    unittest.main()
