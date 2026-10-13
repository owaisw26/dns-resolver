import os
import tempfile
import threading
import unittest
from unittest import mock

import parser
import resolver
from dns_message import (
    CLASS_IN,
    Question,
    ResourceRecord,
    TYPE_A,
    TYPE_CNAME,
    TYPE_NS,
)
from resolver import (
    cache_lookup,
    cache_store,
    is_relevant_referral,
    parse_root_hints,
)


class RootHintsTests(unittest.TestCase):
    def write_hints(self, text):
        fixture = tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", delete=False
        )
        fixture.write(text)
        fixture.close()
        self.addCleanup(lambda: os.unlink(fixture.name))
        return fixture.name

    def test_supported_subset_order_ttl_and_comments(self):
        path = self.write_hints(
            """
            ; comment
            $TTL 100
            $ORIGIN .
            . IN NS A.Root.
            . 200 IN NS b.root.
            ignored. 10 IN AAAA ::1
            A.Root. IN A 127.0.0.2 ; trailing
            A.Root. 150 IN A 127.0.0.3
            b.root. IN 250 A 127.0.0.4
            """
        )
        hints = parse_root_hints(path)
        self.assertEqual(
            [(record.data, record.ttl) for record in hints["ns"]],
            [("A.Root.", 100), ("b.root.", 200)],
        )
        self.assertEqual(
            [(record.data, record.ttl) for record in hints["addresses"]],
            [
                ("127.0.0.2", 100),
                ("127.0.0.3", 150),
                ("127.0.0.4", 250),
            ],
        )
        self.assertEqual(
            hints["root_ips"],
            ("127.0.0.2", "127.0.0.3", "127.0.0.4"),
        )

    def test_missing_ttl_defaults_to_zero(self):
        path = self.write_hints(
            ". IN NS a.root.\na.root. IN A 127.0.0.2\n"
        )
        hints = parse_root_hints(path)
        self.assertEqual(hints["ns"][0].ttl, 0)
        self.assertEqual(hints["addresses"][0].ttl, 0)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.cache = {}
        self.lock = threading.Lock()

    def test_store_hit_and_ttl_floor(self):
        records = (
            ResourceRecord(
                "Alias.Example.", TYPE_CNAME, CLASS_IN, 10, "Target.Example."
            ),
            ResourceRecord(
                "Target.Example.", TYPE_A, CLASS_IN, 20, "192.0.2.1"
            ),
        )
        cache_store(records, self.cache, self.lock, now=100.0)
        result = cache_lookup(
            Question("ALIAS.example", TYPE_A, CLASS_IN),
            self.cache,
            self.lock,
            now=102.2,
        )
        self.assertEqual([record.rtype for record in result], [
            TYPE_CNAME,
            TYPE_A,
        ])
        self.assertEqual([record.ttl for record in result], [7, 17])

    def test_expired_or_incomplete_chain_is_a_miss(self):
        records = (
            ResourceRecord(
                "alias.example.", TYPE_CNAME, CLASS_IN, 2, "target.example."
            ),
            ResourceRecord(
                "target.example.", TYPE_A, CLASS_IN, 10, "192.0.2.1"
            ),
        )
        cache_store(records, self.cache, self.lock, now=10.0)
        self.assertIsNone(
            cache_lookup(
                Question("alias.example.", TYPE_A, CLASS_IN),
                self.cache,
                self.lock,
                now=12.0,
            )
        )

    def test_zero_ttl_is_not_stored(self):
        cache_store(
            (
                ResourceRecord(
                    "example.", TYPE_A, CLASS_IN, 0, "192.0.2.1"
                ),
            ),
            self.cache,
            self.lock,
            now=1.0,
        )
        self.assertEqual(self.cache, {})

    def test_subsecond_remaining_ttl_is_expired(self):
        record = ResourceRecord(
            "example.", TYPE_A, CLASS_IN, 1, "192.0.2.1"
        )
        self.cache[("example.", TYPE_A, CLASS_IN)] = [(record, 10.5)]
        self.assertIsNone(
            cache_lookup(
                Question("example.", TYPE_A, CLASS_IN),
                self.cache,
                self.lock,
                now=10.0,
            )
        )

    def test_storing_an_rrset_replaces_older_entries(self):
        first = ResourceRecord(
            "example.", TYPE_A, CLASS_IN, 30, "192.0.2.1"
        )
        second = ResourceRecord(
            "example.", TYPE_A, CLASS_IN, 30, "192.0.2.2"
        )
        cache_store((first,), self.cache, self.lock, now=1.0)
        cache_store((second,), self.cache, self.lock, now=2.0)
        result = cache_lookup(
            Question("example.", TYPE_A, CLASS_IN),
            self.cache,
            self.lock,
            now=3.0,
        )
        self.assertEqual([record.data for record in result], ["192.0.2.2"])

    def test_direct_cname_query_does_not_chase(self):
        records = (
            ResourceRecord(
                "alias.example.", TYPE_CNAME, CLASS_IN, 10, "target.example."
            ),
            ResourceRecord(
                "target.example.", TYPE_A, CLASS_IN, 10, "192.0.2.1"
            ),
        )
        cache_store(records, self.cache, self.lock, now=1.0)
        result = cache_lookup(
            Question("alias.example.", TYPE_CNAME, CLASS_IN),
            self.cache,
            self.lock,
            now=2.0,
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].rtype, TYPE_CNAME)

    def test_conflicting_cached_cname_targets_are_a_miss(self):
        key = ("alias.example.", TYPE_CNAME, CLASS_IN)
        self.cache[key] = [
            (
                ResourceRecord(
                    "alias.example.",
                    TYPE_CNAME,
                    CLASS_IN,
                    10,
                    "one.example.",
                ),
                20.0,
            ),
            (
                ResourceRecord(
                    "alias.example.",
                    TYPE_CNAME,
                    CLASS_IN,
                    10,
                    "two.example.",
                ),
                20.0,
            ),
        ]
        self.assertIsNone(
            cache_lookup(
                Question("alias.example.", TYPE_A, CLASS_IN),
                self.cache,
                self.lock,
                now=1.0,
            )
        )


class RuntimeCacheTests(unittest.TestCase):
    def setUp(self):
        self.resolver = resolver.Resolver.__new__(resolver.Resolver)
        self.resolver.cache = {}
        self.resolver.cache_lock = threading.Lock()

    def test_exactly_ten_cached_cnames_can_reach_a_final_answer(self):
        records = []
        for index in range(10):
            records.append(
                resolver.DNSRecord(
                    f"{index}.example.",
                    60,
                    resolver.TYPE_CNAME,
                    resolver.CLASS_IN,
                    f"{index + 1}.example.",
                )
            )
        records.append(
            resolver.DNSRecord(
                "10.example.",
                60,
                resolver.TYPE_A,
                resolver.CLASS_IN,
                "192.0.2.10",
            )
        )
        with mock.patch.object(resolver.time, "monotonic", return_value=10.0):
            self.resolver.cache_records(records)
        with mock.patch.object(resolver.time, "monotonic", return_value=11.0):
            result = self.resolver.cached(
                parser.Question("0.example.", resolver.TYPE_A, resolver.CLASS_IN)
            )
        self.assertEqual(len(result), 11)
        self.assertEqual(result[-1].data, "192.0.2.10")


class ReferralValidationTests(unittest.TestCase):
    def test_referral_must_move_down_a_relevant_dns_branch(self):
        self.assertTrue(
            is_relevant_referral("com.", "www.example.com.", ".")
        )
        self.assertTrue(
            is_relevant_referral(
                "example.com.", "www.example.com.", "com."
            )
        )
        self.assertFalse(
            is_relevant_referral("unrelated.net.", "www.example.com.", ".")
        )
        self.assertFalse(
            is_relevant_referral("com.", "www.example.com.", "com.")
        )


if __name__ == "__main__":
    unittest.main()
