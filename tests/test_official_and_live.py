import glob
import os
import unittest

from dns_message import CLASS_IN, Question, TYPE_A, format_message, parse_message
import resolver


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OFFICIAL_FIXTURES = os.path.join(PROJECT_ROOT, "dns-assignment-resources")


class OfficialFixtureTests(unittest.TestCase):
    def test_released_binary_messages(self):
        fixtures = sorted(glob.glob(os.path.join(OFFICIAL_FIXTURES, "*.bin")))
        self.assertTrue(fixtures, "released DNS packet fixtures are missing")
        for fixture in fixtures:
            with self.subTest(fixture=os.path.basename(fixture)):
                with open(fixture, "rb") as fixture_file:
                    parsed = parse_message(fixture_file.read())
                output = format_message(parsed)
                self.assertIn("--- QUESTIONS ---", output)
                self.assertIn("--- ADDITIONAL ---", output)

    def test_released_root_hints(self):
        path = os.path.join(OFFICIAL_FIXTURES, "named.root")
        self.assertTrue(os.path.exists(path), "released root hints are missing")
        hints = resolver.parse_root_hints(path)
        self.assertGreater(len(hints["ns"]), 0)
        self.assertGreater(len(hints["root_ips"]), 0)


@unittest.skipUnless(
    os.environ.get("RUN_LIVE_DNS") == "1",
    "set RUN_LIVE_DNS=1 for the optional Internet smoke test",
)
class LiveDnsSmokeTests(unittest.TestCase):
    def test_iterative_example_com_a(self):
        path = os.environ.get(
            "DNS_ROOT_HINTS",
            os.path.join(OFFICIAL_FIXTURES, "named.root"),
        )
        if not os.path.exists(path):
            self.skipTest("set DNS_ROOT_HINTS to a root hints file")
        hints = resolver.parse_root_hints(path)
        result = resolver.resolve_question(
            Question("example.com.", TYPE_A, CLASS_IN),
            hints,
            timeout=2,
        )
        self.assertEqual(result.rcode, 0)
        self.assertTrue(
            any(record.rtype == TYPE_A for record in result.answers)
        )


if __name__ == "__main__":
    unittest.main()
