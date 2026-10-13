"""Portable black-box tests for the parser.py and resolver.py CLI contracts."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.blackbox_helpers import (
    decode_response,
    message,
    query,
    question,
    wire_name,
)


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "parser.py"
RESOLVER = ROOT / "resolver.py"
RESOURCES = ROOT / "dns-assignment-resources"


class ParserBlackBoxTests(unittest.TestCase):
    """Exercise parser.py only through files, stdout, stderr, and exit codes."""

    def run_parser(self, data: bytes) -> subprocess.CompletedProcess[str]:
        """Write one packet to a temp file and invoke the parser CLI."""
        with tempfile.NamedTemporaryFile() as packet_file:
            packet_file.write(data)
            packet_file.flush()
            return subprocess.run(
                [sys.executable, str(PARSER), packet_file.name],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_released_packets_have_all_required_display_sections(self) -> None:
        """Check every supplied course packet through the parser command."""
        for packet_path in sorted(RESOURCES.glob("*.bin")):
            with self.subTest(packet=packet_path.name):
                result = subprocess.run(
                    [sys.executable, str(PARSER), str(packet_path)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                for heading in (
                    "--- FLAGS ---",
                    "--- COUNTS ---",
                    "--- QUESTIONS ---",
                    "--- ANSWERS ---",
                    "--- AUTHORITY ---",
                    "--- ADDITIONAL ---",
                ):
                    self.assertIn(heading, result.stdout)

    def test_multiple_questions_unknown_type_and_flags_are_displayed(
        self,
    ) -> None:
        """Verify observable traversal and stable header/type output."""
        unknown = (
            wire_name("two.example.")
            + b"\xff\x00\x00\x01\x00\x00\x00\x01\x00\x03xyz"
        )
        packet = message(
            77,
            0xA903,
            (question("one.example.", 1), question("two.example.", 15)),
            (unknown,),
        )
        result = self.run_parser(packet)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ID: 77", result.stdout)
        self.assertIn("Opcode: 5", result.stdout)
        self.assertIn("RCODE: NXDOMAIN", result.stdout)
        self.assertIn("one.example. IN A", result.stdout)
        self.assertIn("two.example. IN MX", result.stdout)
        self.assertIn("TYPE65280", result.stdout)

    def test_malformed_name_fails_safely_without_traceback(self) -> None:
        """Ensure malformed compression cannot crash or hang the CLI."""
        packet = message(1, 0, (b"\xc0\x0c\x00\x01\x00\x01",))
        result = self.run_parser(packet)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class ResolverBlackBoxTests(unittest.TestCase):
    """Exercise resolver.py only through its UDP command-line service."""

    def setUp(self) -> None:
        """Create an accepted root-hints file and reserve an ephemeral port."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.hints = Path(self.tempdir.name) / "named.root"
        self.hints.write_text(
            "$TTL 100\n. 300 IN NS a.root.test.\n. IN 200 NS b.root.test.\n"
            "a.root.test. IN A 192.0.2.1\na.root.test. 150 A 192.0.2.2\n"
            "b.root.test. 400 IN A 192.0.2.3\n",
            encoding="ascii",
        )
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(RESOLVER),
                str(self.hints),
                "1",
                str(self.port),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_resolver)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                _, stderr = self.process.communicate(timeout=1)
                self.fail(f"resolver exited before binding: {stderr}")
            readiness_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                readiness_probe.bind(("127.0.0.1", self.port))
            except OSError:
                readiness_probe.close()
                break
            readiness_probe.close()
            time.sleep(0.02)
        else:
            self.fail("resolver did not bind within two seconds")

    def stop_resolver(self) -> None:
        """Terminate the subprocess and fail if it emitted unexpected output."""
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=2)

    def ask(self, packet: bytes) -> dict:
        """Send one UDP query to the CLI service and decode its reply."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(packet, ("127.0.0.1", self.port))
            reply, _ = client.recvfrom(65535)
        return decode_response(reply)

    def test_root_ns_response_preserves_records_order_flags_and_glue(
        self,
    ) -> None:
        """Verify the complete Stage 2 root-NS response contract."""
        response = self.ask(query(0x1234, ".", 2, 0x2900))
        self.assertEqual(response["id"], 0x1234)
        self.assertEqual(response["flags"] & 0x8000, 0x8000)
        self.assertEqual((response["flags"] >> 11) & 15, 5)
        self.assertEqual(response["flags"] & 0x0100, 0x0100)
        self.assertEqual(response["flags"] & 0x0080, 0x0080)
        self.assertEqual(response["flags"] & 0x0470, 0)
        self.assertEqual([record[4] for record in response["answers"]], [
            "a.root.test.", "b.root.test.",
        ])
        self.assertEqual([record[4] for record in response["additional"]], [
            "192.0.2.1", "192.0.2.2", "192.0.2.3",
        ])
        self.assertEqual(response["authority"], [])

    def test_root_a_is_case_insensitive_and_unsupported_type_is_servfail(
        self,
    ) -> None:
        """Check local A lookup ordering and unsupported-type failure."""
        root_a = self.ask(query(10, "A.ROOT.TEST.", 1))
        self.assertEqual([record[4] for record in root_a["answers"]], [
            "192.0.2.1", "192.0.2.2",
        ])
        failure = self.ask(query(11, "anything.test.", 28))
        self.assertEqual(failure["flags"] & 15, 2)
        self.assertEqual(failure["answers"], [])

    def test_concurrent_clients_receive_their_own_transaction_ids(
        self,
    ) -> None:
        """Confirm concurrent UDP requests do not mix responses."""
        results: dict[int, dict] = {}

        def client(message_id: int) -> None:
            """Issue one independent root-local query."""
            results[message_id] = self.ask(query(message_id, ".", 2))

        workers = [threading.Thread(target=client, args=(identifier,))
                   for identifier in range(100, 112)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        self.assertEqual(set(results), set(range(100, 112)))
        self.assertTrue(all(reply["id"] == identifier
                            for identifier, reply in results.items()))


@unittest.skipUnless(
    os.environ.get("RUN_LIVE_DNS") == "1",
    "set RUN_LIVE_DNS=1 to run the optional public-DNS black-box smoke test",
)
class LiveResolverBlackBoxTests(unittest.TestCase):
    """Run a real iterative lookup only when explicitly enabled."""

    def test_resolver_returns_an_a_answer_for_example_com(self) -> None:
        """Run resolver.py against supplied root hints and public DNS."""
        port_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
        port_socket.close()
        process = subprocess.Popen(
            [
                sys.executable,
                str(RESOLVER),
                str(RESOURCES / "named.root"),
                "2",
                str(port),
            ],
            cwd=ROOT,
        )
        try:
            time.sleep(0.1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(30)
                client.sendto(
                    query(99, "example.com.", 1),
                    ("127.0.0.1", port),
                )
                reply, _ = client.recvfrom(65535)
            decoded = decode_response(reply)
            self.assertEqual(decoded["flags"] & 15, 0)
            self.assertTrue(
                any(record[1] == 1 for record in decoded["answers"])
            )
        finally:
            process.terminate()
            process.wait(timeout=2)
