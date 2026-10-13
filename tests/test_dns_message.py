import struct
import unittest

from dns_message import (
    CLASS_IN,
    DNSFormatError,
    Question,
    ResourceRecord,
    TYPE_A,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_PTR,
    build_query,
    build_response,
    decode_name,
    encode_message,
    format_message,
    normalize_name,
    parse_message,
)
from tests.wire_helpers import message, question, record, wire_name


class NameDecodingTests(unittest.TestCase):
    def test_uncompressed_and_root_names(self):
        self.assertEqual(decode_name(wire_name("WWW.Example.com."), 0), (
            "WWW.Example.com.",
            len(wire_name("WWW.Example.com.")),
        ))
        self.assertEqual(decode_name(b"\x00", 0), (".", 1))

    def test_pointer_resumes_after_two_bytes(self):
        packet = wire_name("example.com.") + b"\xc0\x00\xaa"
        self.assertEqual(
            decode_name(packet, len(wire_name("example.com."))),
            ("example.com.", len(wire_name("example.com.")) + 2),
        )

    def test_twenty_pointer_jumps_are_allowed(self):
        packet = bytearray()
        for index in range(20):
            packet.extend(struct.pack("!H", 0xC000 | (2 * (index + 1))))
        packet.append(0)
        self.assertEqual(decode_name(bytes(packet), 0), (".", 2))

    def test_more_than_twenty_pointer_jumps_are_rejected(self):
        packet = bytearray()
        for index in range(21):
            packet.extend(struct.pack("!H", 0xC000 | (2 * (index + 1))))
        packet.append(0)
        with self.assertRaises(DNSFormatError):
            decode_name(bytes(packet), 0)

    def test_pointer_loop_and_out_of_range_are_rejected(self):
        with self.assertRaises(DNSFormatError):
            decode_name(b"\xc0\x00", 0)
        with self.assertRaises(DNSFormatError):
            decode_name(b"\xc0\x10", 0)

    def test_reserved_and_overlong_names_are_rejected(self):
        with self.assertRaises(DNSFormatError):
            decode_name(b"\x40\x00", 0)
        long_name = (b"\x3f" + b"a" * 63) * 4 + b"\x00"
        with self.assertRaises(DNSFormatError):
            decode_name(long_name, 0)

    def test_original_rdata_boundary_is_enforced_but_pointer_target_is_not(self):
        target = wire_name("ns.example.")
        packet = target + b"\xc0\x00"
        name, offset = decode_name(packet, len(target), len(target) + 2)
        self.assertEqual((name, offset), ("ns.example.", len(packet)))
        with self.assertRaises(DNSFormatError):
            decode_name(target, 0, 2)


class MessageParsingTests(unittest.TestCase):
    def test_flags_counts_questions_and_all_supported_records(self):
        q = question("Example.COM.", TYPE_A)
        owner_pointer = b"\xc0\x0c"
        answers = (
            record(".", TYPE_A, bytes([192, 0, 2, 1]), 0xFFFFFFFF, owner_wire=owner_pointer),
            record("example.com.", TYPE_NS, wire_name("ns.example.com.")),
            record("www.example.com.", TYPE_CNAME, wire_name("example.com.")),
            record(
                "example.com.",
                TYPE_MX,
                struct.pack("!H", 10) + wire_name("mail.example.com."),
            ),
            record(
                "1.2.0.192.in-addr.arpa.",
                TYPE_PTR,
                wire_name("host.example.com."),
            ),
        )
        packet = message(
            flags=0x8583,
            questions=(q,),
            answers=answers[:2],
            authorities=answers[2:4],
            additionals=answers[4:],
        )
        parsed = parse_message(packet)

        self.assertTrue(parsed.qr)
        self.assertEqual(parsed.opcode, 0)
        self.assertTrue(parsed.aa)
        self.assertFalse(parsed.tc)
        self.assertTrue(parsed.rd)
        self.assertTrue(parsed.ra)
        self.assertEqual(parsed.rcode, 3)
        self.assertEqual(parsed.answers[0].data, "192.0.2.1")
        self.assertEqual(parsed.answers[0].ttl, 0xFFFFFFFF)
        self.assertEqual(parsed.answers[1].data, "ns.example.com.")
        self.assertEqual(parsed.authorities[0].data, "example.com.")
        self.assertEqual(parsed.authorities[1].data, (10, "mail.example.com."))
        self.assertEqual(parsed.additionals[0].data, "host.example.com.")

    def test_multiple_questions_are_traversed(self):
        packet = message(
            questions=(
                question("one.example.", TYPE_A),
                question("two.example.", TYPE_MX),
            )
        )
        parsed = parse_message(packet)
        self.assertEqual([q.name for q in parsed.questions], [
            "one.example.",
            "two.example.",
        ])

    def test_unknown_and_malformed_supported_rdata_are_retained(self):
        packet = message(
            flags=0x8000,
            answers=(
                record("bad.example.", TYPE_A, b"\x01\x02\x03"),
                record("unknown.example.", 41, b"\x00\x01"),
                record("good.example.", TYPE_A, b"\x7f\x00\x00\x01"),
            ),
        )
        parsed = parse_message(packet)
        self.assertEqual(parsed.answers[0].data, b"\x01\x02\x03")
        self.assertEqual(parsed.answers[1].data, b"\x00\x01")
        self.assertEqual(parsed.answers[2].data, "127.0.0.1")
        text = format_message(parsed)
        self.assertIn("MALFORMED_RDATA RDLENGTH 3", text)
        self.assertIn("TYPE41 RDLENGTH 2", text)

    def test_name_rdata_must_end_at_rdlength(self):
        packet = message(
            flags=0x8000,
            answers=(
                record("example.", TYPE_NS, wire_name("ns.example.") + b"\x00"),
                record("good.", TYPE_A, b"\x01\x02\x03\x04"),
            ),
        )
        parsed = parse_message(packet)
        self.assertIsInstance(parsed.answers[0].data, bytes)
        self.assertEqual(parsed.answers[1].data, "1.2.3.4")

    def test_structural_truncation_and_trailing_bytes_are_rejected(self):
        with self.assertRaises(DNSFormatError):
            parse_message(b"\x00" * 11)
        valid = message(questions=(question("example."),))
        with self.assertRaises(DNSFormatError):
            parse_message(valid[:-1])
        with self.assertRaises(DNSFormatError):
            parse_message(valid + b"\x00")


class EncodingTests(unittest.TestCase):
    def test_query_is_non_recursive_and_uncompressed(self):
        q = Question("Example.com.", TYPE_A, CLASS_IN)
        packet = build_query(0xCAFE, q)
        parsed = parse_message(packet)
        self.assertEqual(parsed.message_id, 0xCAFE)
        self.assertFalse(parsed.qr)
        self.assertFalse(parsed.rd)
        self.assertEqual(parsed.questions, (q,))
        self.assertNotIn(b"\xc0", packet[12:])

    def test_response_round_trip_and_compression(self):
        query_packet = message(
            message_id=99,
            flags=0x0100,
            questions=(question("www.example.com."),),
        )
        query_message = parse_message(query_packet)
        answer = ResourceRecord(
            "www.example.com.", TYPE_A, CLASS_IN, 30, "192.0.2.9"
        )
        packet = build_response(query_message, (answer,), aa=True)
        parsed = parse_message(packet)
        self.assertEqual(parsed.message_id, 99)
        self.assertTrue(parsed.qr)
        self.assertTrue(parsed.aa)
        self.assertTrue(parsed.rd)
        self.assertTrue(parsed.ra)
        self.assertEqual(parsed.answers[0].data, "192.0.2.9")
        self.assertIn(b"\xc0\x0c", packet)

    def test_oversized_response_becomes_servfail(self):
        query_message = parse_message(
            message(questions=(question("many.example."),))
        )
        answers = tuple(
            ResourceRecord("many.example.", TYPE_A, CLASS_IN, 30, "192.0.2.1")
            for _ in range(40)
        )
        packet = build_response(query_message, answers)
        parsed = parse_message(packet)
        self.assertLessEqual(len(packet), 512)
        self.assertEqual(parsed.rcode, 2)
        self.assertEqual(parsed.answers, ())

    def test_encode_unknown_raw_record(self):
        packet = encode_message(
            1,
            (),
            (ResourceRecord(".", 99, CLASS_IN, 5, b"\x01\x02"),),
            qr=True,
        )
        self.assertEqual(parse_message(packet).answers[0].data, b"\x01\x02")

    def test_normalization(self):
        self.assertEqual(normalize_name("WWW.Example.COM"), "www.example.com.")
        self.assertEqual(normalize_name("."), ".")


if __name__ == "__main__":
    unittest.main()

