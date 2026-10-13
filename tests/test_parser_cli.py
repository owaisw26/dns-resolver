import os
import subprocess
import sys
import tempfile
import unittest

from tests.wire_helpers import message, question


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARSER = os.path.join(PROJECT_ROOT, "parser.py")


class ParserCliTests(unittest.TestCase):
    def run_parser(self, packet):
        with tempfile.NamedTemporaryFile() as fixture:
            fixture.write(packet)
            fixture.flush()
            return subprocess.run(
                [sys.executable, PARSER, fixture.name],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_readable_required_output(self):
        result = self.run_parser(
            message(message_id=44325, questions=(question("unsw.edu.au."),))
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ID: 44325", result.stdout)
        for heading in (
            "--- FLAGS ---",
            "--- COUNTS ---",
            "--- QUESTIONS ---",
            "--- ANSWERS ---",
            "--- AUTHORITY ---",
            "--- ADDITIONAL ---",
        ):
            self.assertIn(heading, result.stdout)
        self.assertIn("unsw.edu.au. IN A", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_malformed_message_has_no_traceback(self):
        result = self.run_parser(b"\x00")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()

