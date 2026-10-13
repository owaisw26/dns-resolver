"""Hidden-test-style regressions for resolver edge-case compliance."""

import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import parser
import resolver
from dns_message import CLASS_IN, TYPE_A, TYPE_CNAME, TYPE_NS, parse_message
from tests.scripted_dns import (
    ScriptedDNSServer,
    free_udp_port,
    make_response,
    read_query,
)
from tests.wire_helpers import message, question, record, wire_name


def query_packet(name, message_id=0x1234, flags=0x0100):
    """Build one independent client A query."""
    return message(
        message_id=message_id,
        flags=flags,
        questions=(question(name, TYPE_A, CLASS_IN),),
    )


def a_record(name, address, *, rclass=CLASS_IN):
    """Build one test A resource record."""
    return record(
        name,
        TYPE_A,
        socket.inet_aton(address),
        rclass=rclass,
    )


class ResolverComplianceRegressions(unittest.TestCase):
    """Exercise corrected compression, resolution, and failover behaviour."""

    def setUp(self):
        self.servers = []
        self.endpoint_patch = mock.patch.object(
            resolver, "UPSTREAM_ENDPOINTS", {}
        )
        self.endpoint_patch.start()
        self.addCleanup(self.endpoint_patch.stop)
        self.cache = {}
        self.cache_lock = threading.Lock()

    def tearDown(self):
        for server in reversed(self.servers):
            server.stop()

    def hints(self, entries):
        """Create and parse a minimal ordered root-hints fixture."""
        fixture = tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", delete=False
        )
        for name, address in entries:
            fixture.write(f". 3600 IN NS {name}\n")
            fixture.write(f"{name} 3600 IN A {address}\n")
        fixture.close()
        self.addCleanup(lambda: os.unlink(fixture.name))
        return resolver.parse_root_hints(fixture.name)

    def start_server(self, address, callback):
        """Map one candidate address to a scripted local DNS endpoint."""
        port = free_udp_port("127.0.0.1")
        server = ScriptedDNSServer(
            "127.0.0.1", port, callback
        ).start()
        resolver.UPSTREAM_ENDPOINTS[address] = ("127.0.0.1", port)
        self.servers.append(server)
        return server

    def process(self, packet, hints, timeout=0.4):
        """Run one packet through isolated resolver state and parse its reply."""
        response = resolver.process_client_query(
            packet, hints, timeout, self.cache, self.cache_lock
        )
        return response, parse_message(response)

    def test_case_insensitive_compression_fits_and_preserves_question(self):
        """Mixed-case owner keys must reuse the original Question suffix."""
        instance = resolver.Resolver.__new__(resolver.Resolver)
        client_question = parser.Question(
            "Long.MixedCase.Response.Example.", TYPE_A, CLASS_IN
        )
        answers = [
            resolver.DNSRecord(
                "LONG.MIXEDCASE.RESPONSE.EXAMPLE.",
                60,
                TYPE_A,
                CLASS_IN,
                f"192.0.2.{index}",
            )
            for index in range(1, 26)
        ]
        packet = instance.build_client_response(
            0xCAFE, 0x1900, client_question, 0, answers, [], True
        )
        decoded = parse_message(packet)

        self.assertLessEqual(len(packet), 512)
        self.assertEqual(decoded.rcode, 0)
        self.assertEqual(decoded.message_id, 0xCAFE)
        self.assertEqual(decoded.questions[0].name, client_question.name)
        self.assertEqual(decoded.opcode, 3)
        self.assertTrue(decoded.rd)
        self.assertTrue(decoded.aa)
        self.assertEqual(len(decoded.answers), 25)
        self.assertGreaterEqual(packet.count(b"\xc0\x0c"), 25)

    def test_same_packet_cname_chain_is_retained_with_nxdomain(self):
        """An authoritative negative packet may carry its complete alias chain."""
        def callback(packet):
            query = read_query(packet)
            if query["name"].lower() == "alias.example.":
                answers = (
                    record(
                        "alias.example.",
                        TYPE_CNAME,
                        wire_name("middle.example."),
                    ),
                    record(
                        "middle.example.",
                        TYPE_CNAME,
                        wire_name("missing.example."),
                    ),
                )
            else:
                answers = (
                    record(
                        "middle2.example.",
                        TYPE_CNAME,
                        wire_name("missing2.example."),
                    ),
                )
            return make_response(packet, flags=0x8403, answers=answers)

        server = self.start_server("127.0.0.2", callback)
        hints = self.hints((("a.root.", "127.0.0.2"),))
        _, single = self.process(query_packet("alias.example.", 1), hints)
        self.assertEqual(single.rcode, 3)
        self.assertEqual(
            [answer.data for answer in single.answers],
            ["middle.example.", "missing.example."],
        )
        self.assertTrue(single.aa)

        # A prior packet plus aliases in the final negative packet clears AA.
        def cross_packet(packet):
            query = read_query(packet)
            if query["name"].lower() == "alias2.example.":
                return make_response(
                    packet,
                    flags=0x8400,
                    answers=(
                        record(
                            "alias2.example.",
                            TYPE_CNAME,
                            wire_name("middle2.example."),
                        ),
                    ),
                )
            return callback(packet)

        server.callback = cross_packet
        _, combined = self.process(query_packet("alias2.example.", 2), hints)
        self.assertEqual(combined.rcode, 3)
        self.assertEqual(
            [answer.data for answer in combined.answers],
            ["middle2.example.", "missing2.example."],
        )
        self.assertFalse(combined.aa)

    def test_cname_consistency_loop_and_record_limit(self):
        """Reject conflicting/looping aliases and permit exactly ten records."""
        def callback(packet):
            query = read_query(packet)
            name = query["name"].lower()
            if name == "conflict.example.":
                answers = (
                    record(name, TYPE_CNAME, wire_name("one.example.")),
                    record(name, TYPE_CNAME, wire_name("two.example.")),
                )
            elif name == "loop.example.":
                answers = (
                    record(name, TYPE_CNAME, wire_name("middle.example.")),
                    record(
                        "middle.example.",
                        TYPE_CNAME,
                        wire_name("loop.example."),
                    ),
                )
            else:
                count = 10 if name == "0.ten.example." else 11
                suffix = "ten.example." if count == 10 else "eleven.example."
                answers = tuple(
                    record(
                        f"{index}.{suffix}",
                        TYPE_CNAME,
                        wire_name(f"{index + 1}.{suffix}"),
                    )
                    for index in range(count)
                ) + (a_record(f"{count}.{suffix}", "192.0.2.10"),)
            return make_response(packet, flags=0x8400, answers=answers)

        self.start_server("127.0.0.2", callback)
        hints = self.hints((("a.root.", "127.0.0.2"),))
        for index, name in enumerate(("conflict.example.", "loop.example.")):
            _, failed = self.process(query_packet(name, index), hints)
            self.assertEqual(failed.rcode, 2)
            self.assertEqual(failed.answers, ())

        _, ten = self.process(query_packet("0.ten.example.", 10), hints)
        _, eleven = self.process(query_packet("0.eleven.example.", 11), hints)
        self.assertEqual(ten.rcode, 0)
        self.assertEqual(len(ten.answers), 11)
        self.assertEqual(eleven.rcode, 2)
        self.assertEqual(eleven.answers, ())

    def test_tc_and_structural_malformed_replies_fail_over_immediately(self):
        """Matching candidate failures must not consume their remaining timeout."""
        def failing(packet):
            query = read_query(packet)
            if query["name"].lower().startswith("tc."):
                return make_response(packet, flags=0x8200)
            valid = make_response(
                packet,
                flags=0x8400,
                answers=(a_record(query["name"], "192.0.2.1"),),
            )
            return valid[:-1]

        def good(packet):
            query = read_query(packet)
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record(query["name"], "192.0.2.55"),),
            )

        self.start_server("127.0.0.2", failing)
        second = self.start_server("127.0.0.5", good)
        hints = self.hints(
            (("a.root.", "127.0.0.2"), ("b.root.", "127.0.0.5"))
        )
        for index, name in enumerate(("tc.example.", "bad.example.")):
            started = time.monotonic()
            _, response = self.process(query_packet(name, index), hints)
            elapsed = time.monotonic() - started
            self.assertEqual(response.answers[0].data, "192.0.2.55")
            self.assertLess(elapsed, 0.3)
        self.assertEqual(second.query_count(), 2)

    def test_non_in_glue_is_ignored_and_nameserver_address_is_resolved(self):
        """Only IN-class A glue may become a referral candidate."""
        def root_callback(packet):
            query = read_query(packet)
            if query["name"].lower() == "www.example.com.":
                return make_response(
                    packet,
                    authorities=(
                        record(
                            "example.com.",
                            TYPE_NS,
                            wire_name("ns.example.net."),
                        ),
                    ),
                    additionals=(
                        a_record(
                            "ns.example.net.", "127.0.0.9", rclass=3
                        ),
                    ),
                )
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("ns.example.net.", "127.0.0.4"),),
            )

        def target_callback(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("www.example.com.", "192.0.2.60"),),
            )

        root = self.start_server("127.0.0.2", root_callback)
        malicious = self.start_server("127.0.0.9", target_callback)
        target = self.start_server("127.0.0.4", target_callback)
        hints = self.hints((("a.root.", "127.0.0.2"),))
        _, response = self.process(query_packet("www.example.com."), hints)
        self.assertEqual(response.answers[-1].data, "192.0.2.60")
        self.assertEqual(root.query_count(), 2)
        self.assertEqual(malicious.query_count(), 0)
        self.assertEqual(target.query_count(), 1)

    def test_socket_failures_fail_over_or_form_client_servfail(self):
        """Recoverable socket errors stay inside candidate resolution."""
        def good(packet):
            query = read_query(packet)
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record(query["name"], "192.0.2.70"),),
            )

        self.start_server("127.0.0.5", good)
        hints = self.hints(
            (("a.root.", "127.0.0.2"), ("b.root.", "127.0.0.5"))
        )
        real_socket = socket.socket
        calls = {"count": 0}

        def one_failure(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("simulated candidate socket failure")
            return real_socket(*args, **kwargs)

        with mock.patch.object(resolver.socket, "socket", side_effect=one_failure):
            _, success = self.process(query_packet("success.example.", 1), hints)
        self.assertEqual(success.answers[0].data, "192.0.2.70")

        flags = (7 << 11) | 0x0100
        with mock.patch.object(
            resolver.socket,
            "socket",
            side_effect=OSError("simulated all-candidate failure"),
        ):
            packet, failed = self.process(
                query_packet("failure.example.", 0xBEEF, flags), hints
            )
        self.assertLessEqual(len(packet), 512)
        self.assertEqual(failed.message_id, 0xBEEF)
        self.assertEqual(failed.opcode, 7)
        self.assertTrue(failed.rd)
        self.assertTrue(failed.ra)
        self.assertFalse(failed.aa)
        self.assertEqual(failed.rcode, 2)
        self.assertEqual(len(failed.questions), 1)
        self.assertEqual(failed.questions[0].name, "failure.example.")
        self.assertEqual(failed.answers, ())
        self.assertEqual(failed.authorities, ())
        self.assertEqual(failed.additionals, ())


if __name__ == "__main__":
    unittest.main()
