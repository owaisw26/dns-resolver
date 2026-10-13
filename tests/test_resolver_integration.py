import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

import resolver
from dns_message import (
    CLASS_IN,
    TYPE_A,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_PTR,
    parse_message,
)
from tests.scripted_dns import (
    ScriptedDNSServer,
    free_udp_port,
    make_response,
    read_query,
)
from tests.wire_helpers import message, question, record, wire_name


def query_packet(name, qtype=TYPE_A, message_id=0x1234):
    return message(
        message_id=message_id,
        flags=0x0100,
        questions=(question(name, qtype, CLASS_IN),),
    )


def a_record(name, address, ttl=60, owner_wire=None):
    return record(
        name,
        TYPE_A,
        socket.inet_aton(address),
        ttl=ttl,
        owner_wire=owner_wire,
    )


class ResolverIntegrationTests(unittest.TestCase):
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

    def hints_file(self, entries=None):
        if entries is None:
            entries = (("a.root.", "127.0.0.2"),)
        fixture = tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", delete=False
        )
        for name, address in entries:
            fixture.write(". 3600 IN NS {}\n".format(name))
            fixture.write("{} 3600 IN A {}\n".format(name, address))
        fixture.close()
        self.addCleanup(lambda: os.unlink(fixture.name))
        return fixture.name

    def start_server(self, address, callback):
        port = free_udp_port("127.0.0.1")
        server = ScriptedDNSServer(
            "127.0.0.1", port, callback
        ).start()
        resolver.UPSTREAM_ENDPOINTS[address] = ("127.0.0.1", port)
        self.servers.append(server)
        return server

    def process(self, packet, hints, timeout=0.2):
        return parse_message(
            resolver.process_client_query(
                packet,
                hints,
                timeout,
                self.cache,
                self.cache_lock,
            )
        )

    def install_three_level_hierarchy(self, auth_callback):
        def root_callback(packet):
            return make_response(
                packet,
                authorities=(
                    record("com.", TYPE_NS, wire_name("ns.com.")),
                ),
                additionals=(
                    a_record("unrelated.", "127.0.0.9"),
                    a_record("ns.com.", "127.0.0.3"),
                ),
            )

        def tld_callback(packet):
            return make_response(
                packet,
                authorities=(
                    record(
                        "example.com.",
                        TYPE_NS,
                        wire_name("ns.example.com."),
                    ),
                ),
                additionals=(
                    a_record("ns.example.com.", "127.0.0.4"),
                ),
            )

        root = self.start_server("127.0.0.2", root_callback)
        tld = self.start_server("127.0.0.3", tld_callback)
        auth = self.start_server("127.0.0.4", auth_callback)
        hints = resolver.parse_root_hints(self.hints_file())
        return hints, root, tld, auth

    def test_root_tld_authoritative_resolution_and_cache_hit(self):
        def auth_callback(packet):
            query = read_query(packet)
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    a_record(
                        query["name"],
                        "192.0.2.10",
                        ttl=30,
                        owner_wire=b"\xc0\x0c",
                    ),
                ),
            )

        hints, root, tld, auth = self.install_three_level_hierarchy(
            auth_callback
        )
        first = self.process(
            query_packet("www.example.com.", message_id=1), hints
        )
        counts = (
            root.query_count(),
            tld.query_count(),
            auth.query_count(),
        )
        second = self.process(
            query_packet("WWW.EXAMPLE.COM.", message_id=2), hints
        )

        self.assertEqual(first.answers[0].data, "192.0.2.10")
        self.assertTrue(first.aa)
        self.assertEqual(second.message_id, 2)
        self.assertEqual(second.answers[0].data, "192.0.2.10")
        self.assertFalse(second.aa)
        self.assertLessEqual(second.answers[0].ttl, first.answers[0].ttl)
        self.assertEqual(
            (
                root.query_count(),
                tld.query_count(),
                auth.query_count(),
            ),
            counts,
        )
        for query in root.queries + tld.queries + auth.queries:
            self.assertEqual(query["flags"], 0)

    def test_supported_record_types_and_direct_cname(self):
        def callback(packet):
            query = read_query(packet)
            if query["type"] == TYPE_A:
                answer = a_record(query["name"], "192.0.2.1")
            elif query["type"] == TYPE_NS:
                answer = record(
                    query["name"], TYPE_NS, wire_name("ns.example.")
                )
            elif query["type"] == TYPE_MX:
                answer = record(
                    query["name"],
                    TYPE_MX,
                    struct.pack("!H", 10) + wire_name("mail.example."),
                )
            elif query["type"] == TYPE_PTR:
                answer = record(
                    query["name"],
                    TYPE_PTR,
                    wire_name("host.example."),
                )
            else:
                answer = record(
                    query["name"],
                    TYPE_CNAME,
                    wire_name("target.example."),
                )
            return make_response(
                packet, flags=0x8400, answers=(answer,)
            )

        root = self.start_server("127.0.0.2", callback)
        hints = resolver.parse_root_hints(self.hints_file())
        expected = {
            TYPE_A: "192.0.2.1",
            TYPE_NS: "ns.example.",
            TYPE_MX: (10, "mail.example."),
            TYPE_PTR: "host.example.",
            TYPE_CNAME: "target.example.",
        }
        for index, (qtype, data) in enumerate(expected.items()):
            response = self.process(
                query_packet(
                    "4.3.2.1.in-addr.arpa."
                    if qtype == TYPE_PTR
                    else "test.example.",
                    qtype,
                    index,
                ),
                hints,
            )
            self.assertEqual(response.rcode, 0)
            self.assertEqual(response.answers[-1].data, data)
        self.assertEqual(root.query_count(), len(expected))

    def test_same_packet_and_cross_packet_cname_chains(self):
        def same_packet(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    record(
                        "alias.example.",
                        TYPE_CNAME,
                        wire_name("middle.example."),
                    ),
                    record(
                        "middle.example.",
                        TYPE_CNAME,
                        wire_name("target.example."),
                    ),
                    a_record("target.example.", "192.0.2.20"),
                ),
            )

        server = self.start_server("127.0.0.2", same_packet)
        hints = resolver.parse_root_hints(self.hints_file())
        response = self.process(query_packet("alias.example."), hints)
        self.assertEqual(
            [record.rtype for record in response.answers],
            [TYPE_CNAME, TYPE_CNAME, TYPE_A],
        )
        self.assertTrue(response.aa)
        server.stop()
        self.servers.remove(server)

        def cross_packet(packet):
            query = read_query(packet)
            if query["name"].lower() == "alias.example.":
                answers = (
                    record(
                        query["name"],
                        TYPE_CNAME,
                        wire_name("target.example."),
                    ),
                )
            else:
                answers = (a_record(query["name"], "192.0.2.21"),)
            return make_response(packet, flags=0x8400, answers=answers)

        server = self.start_server("127.0.0.2", cross_packet)
        self.cache.clear()
        response = self.process(query_packet("alias.example.", message_id=2), hints)
        self.assertEqual(
            [record.rtype for record in response.answers],
            [TYPE_CNAME, TYPE_A],
        )
        self.assertFalse(response.aa)
        self.assertEqual(server.query_count(), 2)

    def test_cname_loop_and_overlong_chain_return_servfail(self):
        def loop_callback(packet):
            query = read_query(packet)
            target = (
                "two.example."
                if query["name"].lower() == "one.example."
                else "one.example."
            )
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    record(query["name"], TYPE_CNAME, wire_name(target)),
                ),
            )

        server = self.start_server("127.0.0.2", loop_callback)
        hints = resolver.parse_root_hints(self.hints_file())
        response = self.process(query_packet("one.example."), hints)
        self.assertEqual(response.rcode, 2)
        self.assertEqual(response.answers, ())
        server.stop()
        self.servers.remove(server)

        def long_chain(packet):
            answers = []
            for index in range(11):
                answers.append(
                    record(
                        "{}.example.".format(index),
                        TYPE_CNAME,
                        wire_name("{}.example.".format(index + 1)),
                    )
                )
            answers.append(a_record("11.example.", "192.0.2.1"))
            return make_response(
                packet, flags=0x8400, answers=tuple(answers)
            )

        self.start_server("127.0.0.2", long_chain)
        response = self.process(query_packet("0.example."), hints)
        self.assertEqual(response.rcode, 2)

    def test_authoritative_nodata_and_nxdomain_are_final(self):
        def callback(packet):
            query = read_query(packet)
            flags = (
                0x8403
                if query["name"].lower().startswith("missing")
                else 0x8400
            )
            return make_response(packet, flags=flags)

        server = self.start_server("127.0.0.2", callback)
        hints = resolver.parse_root_hints(self.hints_file())
        nodata = self.process(query_packet("empty.example."), hints)
        nxdomain = self.process(query_packet("missing.example."), hints)
        self.assertEqual(nodata.rcode, 0)
        self.assertEqual(nodata.answers, ())
        self.assertTrue(nodata.aa)
        self.assertEqual(nxdomain.rcode, 3)
        self.assertTrue(nxdomain.aa)
        self.assertEqual(server.query_count(), 2)

    def test_cname_then_nxdomain_preserves_chain(self):
        def callback(packet):
            query = read_query(packet)
            if query["name"].lower() == "alias.example.":
                return make_response(
                    packet,
                    flags=0x8400,
                    answers=(
                        record(
                            query["name"],
                            TYPE_CNAME,
                            wire_name("missing.example."),
                        ),
                    ),
                )
            return make_response(packet, flags=0x8403)

        server = self.start_server("127.0.0.2", callback)
        hints = resolver.parse_root_hints(self.hints_file())
        response = self.process(query_packet("alias.example."), hints)
        self.assertEqual(response.rcode, 3)
        self.assertEqual(len(response.answers), 1)
        self.assertEqual(response.answers[0].rtype, TYPE_CNAME)
        self.assertFalse(response.aa)
        self.assertEqual(server.query_count(), 2)

    def test_candidate_failover_and_mismatched_id_ignored(self):
        def truncated(packet):
            return make_response(packet, flags=0x8200)

        def good(packet):
            wrong = make_response(
                packet,
                flags=0x8400,
                answers=(a_record("test.example.", "192.0.2.30"),),
                message_id=(read_query(packet)["id"] + 1) & 0xFFFF,
            )
            wrong_question = make_response(
                packet,
                flags=0x8400,
                answers=(a_record("other.example.", "192.0.2.30"),),
                question_wire=question("other.example.", TYPE_A, CLASS_IN),
            )
            correct = make_response(
                packet,
                flags=0x8400,
                answers=(a_record("test.example.", "192.0.2.31"),),
            )
            return (wrong, wrong_question, correct)

        first = self.start_server("127.0.0.2", truncated)
        second = self.start_server("127.0.0.5", good)
        hints = resolver.parse_root_hints(
            self.hints_file(
                (
                    ("a.root.", "127.0.0.2"),
                    ("b.root.", "127.0.0.5"),
                )
            )
        )
        response = self.process(query_packet("test.example."), hints)
        self.assertEqual(response.answers[0].data, "192.0.2.31")
        self.assertEqual(first.query_count(), 1)
        self.assertEqual(second.query_count(), 1)

    def test_unrelated_authority_ns_is_not_followed_as_a_referral(self):
        def unrelated_referral(packet):
            return make_response(
                packet,
                authorities=(
                    record(
                        "unrelated.net.",
                        TYPE_NS,
                        wire_name("ns.unrelated.net."),
                    ),
                ),
                additionals=(
                    a_record("ns.unrelated.net.", "127.0.0.9"),
                ),
            )

        def malicious(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("test.example.", "192.0.2.99"),),
            )

        def good(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("test.example.", "192.0.2.31"),),
            )

        first = self.start_server("127.0.0.2", unrelated_referral)
        unrelated = self.start_server("127.0.0.9", malicious)
        second = self.start_server("127.0.0.5", good)
        hints = resolver.parse_root_hints(
            self.hints_file(
                (
                    ("a.root.", "127.0.0.2"),
                    ("b.root.", "127.0.0.5"),
                )
            )
        )
        response = self.process(query_packet("test.example."), hints)
        self.assertEqual(response.answers[0].data, "192.0.2.31")
        self.assertEqual(first.query_count(), 1)
        self.assertEqual(unrelated.query_count(), 0)
        self.assertEqual(second.query_count(), 1)

    def test_malformed_supported_rdata_fails_over(self):
        def malformed(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    record("test.example.", TYPE_A, b"\x01\x02\x03"),
                ),
            )

        def good(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("test.example.", "192.0.2.32"),),
            )

        first = self.start_server("127.0.0.2", malformed)
        second = self.start_server("127.0.0.5", good)
        hints = resolver.parse_root_hints(
            self.hints_file(
                (
                    ("a.root.", "127.0.0.2"),
                    ("b.root.", "127.0.0.5"),
                )
            )
        )
        response = self.process(query_packet("test.example."), hints)
        self.assertEqual(response.answers[0].data, "192.0.2.32")
        self.assertEqual(first.query_count(), 1)
        self.assertEqual(second.query_count(), 1)

    def test_no_glue_referral_uses_nested_a_lookup(self):
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
                )
            return make_response(
                packet,
                authorities=(
                    record("net.", TYPE_NS, wire_name("ns.net.")),
                ),
                additionals=(a_record("ns.net.", "127.0.0.3"),),
            )

        def net_callback(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("ns.example.net.", "127.0.0.4"),),
            )

        def target_callback(packet):
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record("www.example.com.", "192.0.2.40"),),
            )

        root = self.start_server("127.0.0.2", root_callback)
        net = self.start_server("127.0.0.3", net_callback)
        target = self.start_server("127.0.0.4", target_callback)
        hints = resolver.parse_root_hints(self.hints_file())
        response = self.process(query_packet("www.example.com."), hints)
        self.assertEqual(response.answers[-1].data, "192.0.2.40")
        self.assertEqual(root.query_count(), 2)
        self.assertEqual(net.query_count(), 1)
        self.assertEqual(target.query_count(), 1)

    def test_referral_depth_limit_returns_servfail(self):
        labels = [
            "a", "b", "c", "d", "e", "f",
            "g", "h", "i", "j", "k", "example",
        ]
        referrals_sent = {"count": 0}

        def callback(packet):
            referrals_sent["count"] += 1
            depth = referrals_sent["count"]
            zone = ".".join(labels[-depth:]) + "."
            nameserver = "ns{}.servers.".format(depth)
            return make_response(
                packet,
                authorities=(
                    record(zone, TYPE_NS, wire_name(nameserver)),
                ),
                additionals=(
                    a_record(nameserver, "127.0.0.2"),
                ),
            )

        server = self.start_server("127.0.0.2", callback)
        hints = resolver.parse_root_hints(self.hints_file())
        response = self.process(
            query_packet(".".join(labels) + "."),
            hints,
        )
        self.assertEqual(response.rcode, 2)
        self.assertEqual(response.answers, ())
        self.assertEqual(server.query_count(), 11)

    def test_fifty_attempt_limit_stops_before_extra_candidates(self):
        server = self.start_server(
            "192.0.2.1",
            lambda packet: make_response(packet, flags=0x8005),
        )
        endpoint = resolver.UPSTREAM_ENDPOINTS["192.0.2.1"]
        entries = []
        for index in range(1, 52):
            address = "192.0.2.{}".format(index)
            entries.append(("root{}.servers.".format(index), address))
            resolver.UPSTREAM_ENDPOINTS[address] = endpoint
        hints = resolver.parse_root_hints(self.hints_file(tuple(entries)))
        response = self.process(query_packet("attempts.example."), hints)
        self.assertEqual(response.rcode, 2)
        self.assertEqual(server.query_count(), 50)

    def test_local_answers_and_unsupported_type_do_not_contact_upstream(self):
        upstream = self.start_server(
            "127.0.0.2",
            lambda packet: make_response(packet, flags=0x8400),
        )
        hints = resolver.parse_root_hints(self.hints_file())
        root_ns = self.process(query_packet(".", TYPE_NS), hints)
        root_a = self.process(query_packet("A.ROOT.", TYPE_A), hints)
        unsupported = self.process(query_packet("example.", 28), hints)
        self.assertEqual(root_ns.answers[0].rtype, TYPE_NS)
        self.assertEqual(root_ns.additionals[0].data, "127.0.0.2")
        self.assertFalse(root_ns.aa)
        self.assertEqual(root_a.answers[0].data, "127.0.0.2")
        self.assertEqual(unsupported.rcode, 2)
        self.assertEqual(upstream.query_count(), 0)

    def test_ttl_zero_and_oversized_answers_are_not_cached(self):
        mode = {"large": False}

        def callback(packet):
            query = read_query(packet)
            if mode["large"]:
                answers = tuple(
                    a_record(query["name"], "192.0.2.1", ttl=30)
                    for _ in range(40)
                )
            else:
                answers = (a_record(query["name"], "192.0.2.1", ttl=0),)
            return make_response(packet, flags=0x8400, answers=answers)

        server = self.start_server("127.0.0.2", callback)
        hints = resolver.parse_root_hints(self.hints_file())
        self.process(query_packet("zero.example.", message_id=1), hints)
        self.process(query_packet("zero.example.", message_id=2), hints)
        self.assertEqual(server.query_count(), 2)

        mode["large"] = True
        first = self.process(query_packet("large.example.", message_id=3), hints)
        second = self.process(query_packet("large.example.", message_id=4), hints)
        self.assertEqual(first.rcode, 2)
        self.assertEqual(second.rcode, 2)
        self.assertEqual(server.query_count(), 4)


class ResolverConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.endpoint_patch = mock.patch.object(
            resolver, "UPSTREAM_ENDPOINTS", {}
        )
        self.endpoint_patch.start()
        self.server = None
        self.stop_event = None
        self.resolver_thread = None
        self.hints_path = None

    def tearDown(self):
        if self.stop_event is not None:
            self.stop_event.set()
        if self.resolver_thread is not None:
            self.resolver_thread.join(timeout=2)
        if self.server is not None:
            self.server.stop()
        if self.hints_path is not None:
            os.unlink(self.hints_path)
        self.endpoint_patch.stop()

    def start_resolver(self, callback):
        upstream_port = free_udp_port("127.0.0.1")
        self.server = ScriptedDNSServer(
            "127.0.0.1", upstream_port, callback
        ).start()
        resolver.UPSTREAM_ENDPOINTS["127.0.0.2"] = (
            "127.0.0.1",
            upstream_port,
        )
        fixture = tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", delete=False
        )
        fixture.write(". 3600 IN NS a.root.\n")
        fixture.write("a.root. 3600 IN A 127.0.0.2\n")
        fixture.close()
        self.hints_path = fixture.name

        listen_port = free_udp_port("127.0.0.1")
        self.stop_event = threading.Event()
        ready = threading.Event()
        self.resolver_thread = threading.Thread(
            target=resolver.serve,
            args=(self.hints_path, 1, listen_port, self.stop_event, ready),
            daemon=True,
        )
        self.resolver_thread.start()
        self.assertTrue(ready.wait(2))
        return listen_port

    def ask(self, port, name, message_id, results, key):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        started = time.monotonic()
        try:
            client.sendto(
                query_packet(name, TYPE_A, message_id),
                ("127.0.0.1", port),
            )
            packet, _ = client.recvfrom(65535)
            results[key] = (time.monotonic() - started, parse_message(packet))
        finally:
            client.close()

    def test_slow_query_does_not_block_fast_query(self):
        def callback(packet):
            query = read_query(packet)
            if query["name"].lower() == "slow.example.":
                time.sleep(0.3)
                address = "192.0.2.50"
            else:
                address = "192.0.2.51"
            return make_response(
                packet,
                flags=0x8400,
                answers=(a_record(query["name"], address),),
            )

        port = self.start_resolver(callback)
        results = {}
        slow = threading.Thread(
            target=self.ask,
            args=(port, "slow.example.", 100, results, "slow"),
        )
        fast = threading.Thread(
            target=self.ask,
            args=(port, "fast.example.", 200, results, "fast"),
        )
        slow.start()
        time.sleep(0.03)
        fast.start()
        slow.join(2)
        fast.join(2)

        self.assertEqual(results["slow"][1].message_id, 100)
        self.assertEqual(results["fast"][1].message_id, 200)
        self.assertLess(results["fast"][0], 0.2)
        self.assertGreater(results["slow"][0], 0.25)

    def test_parallel_client_ids_and_answers_do_not_mix(self):
        def callback(packet):
            query = read_query(packet)
            last_label = int(query["name"].split(".", 1)[0])
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    a_record(
                        query["name"],
                        "192.0.2.{}".format(last_label + 1),
                    ),
                ),
            )

        port = self.start_resolver(callback)
        results = {}
        clients = [
            threading.Thread(
                target=self.ask,
                args=(
                    port,
                    "{}.example.".format(index),
                    1000 + index,
                    results,
                    index,
                ),
            )
            for index in range(12)
        ]
        for client in clients:
            client.start()
        for client in clients:
            client.join(2)

        self.assertEqual(len(results), 12)
        for index in range(12):
            response = results[index][1]
            self.assertEqual(response.message_id, 1000 + index)
            self.assertEqual(
                response.answers[0].data,
                "192.0.2.{}".format(index + 1),
            )

    def test_concurrent_client_stress_preserves_state_and_cache(self):
        """Stress cold and warm concurrent waves without response cross-talk."""
        wave_size = 40
        wave_count = 5

        def callback(packet):
            """Reorder cold replies to expose accidental shared state."""
            query = read_query(packet)
            slot = int(query["name"].split(".", 1)[0])
            time.sleep((wave_size - slot) % 8 * 0.003)
            return make_response(
                packet,
                flags=0x8400,
                answers=(
                    a_record(
                        query["name"],
                        "192.0.2.{}".format(slot + 1),
                    ),
                ),
            )

        # Start one real UDP resolver backed by the deterministic test server.
        port = self.start_resolver(callback)
        results = {}
        failures = []
        result_lock = threading.Lock()

        def client(wave, slot, barrier):
            """Release with its wave and safely publish one decoded response."""
            local = {}
            key = (wave, slot)
            message_id = 20000 + wave * wave_size + slot
            try:
                barrier.wait(timeout=2)
                self.ask(
                    port,
                    "{}.stress.example.".format(slot),
                    message_id,
                    local,
                    key,
                )
                with result_lock:
                    results[key] = local[key]
            except Exception as error:
                with result_lock:
                    failures.append((key, error))

        # Send five simultaneous waves: one cold and four served from cache.
        for wave in range(wave_count):
            barrier = threading.Barrier(wave_size + 1)
            workers = [
                threading.Thread(
                    target=client,
                    args=(wave, slot, barrier),
                )
                for slot in range(wave_size)
            ]
            for worker in workers:
                worker.start()
            barrier.wait(timeout=2)
            for worker in workers:
                worker.join(timeout=3)
            self.assertFalse(any(worker.is_alive() for worker in workers))

        # Verify all 200 replies retained their request-specific ID and answer.
        self.assertEqual(failures, [])
        self.assertEqual(len(results), wave_size * wave_count)
        for wave in range(wave_count):
            for slot in range(wave_size):
                response = results[(wave, slot)][1]
                self.assertEqual(
                    response.message_id,
                    20000 + wave * wave_size + slot,
                )
                self.assertEqual(
                    response.answers[0].data,
                    "192.0.2.{}".format(slot + 1),
                )

        # Only the first wave should contact upstream after cache population.
        self.assertEqual(self.server.query_count(), wave_size)


if __name__ == "__main__":
    unittest.main()
