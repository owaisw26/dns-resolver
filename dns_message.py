"""Reusable DNS-message compatibility API built on the assignment parser.

The command-line parser remains in :mod:`parser`; this module lets the supplied
unit tests exercise the same wire rules programmatically.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

import parser

CLASS_IN = 1
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_PTR, TYPE_MX = 1, 2, 5, 12, 15
DNSFormatError = parser.DNSParseError


def normalize_name(value: str) -> str:
    """Return a fully qualified lowercase DNS comparison name."""
    return value.lower() if value.endswith(".") else value.lower() + "."


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass(frozen=True)
class ResourceRecord:
    owner: str
    rtype: int
    rclass: int
    ttl: int
    data: object


@dataclass(frozen=True)
class Message:
    message_id: int
    flags: int
    questions: tuple[Question, ...]
    answers: tuple[ResourceRecord, ...]
    authorities: tuple[ResourceRecord, ...]
    additionals: tuple[ResourceRecord, ...]

    @property
    def qr(self):
        """Return whether this message is a response."""
        return bool(self.flags & 0x8000)

    @property
    def opcode(self):
        """Return the four-bit DNS opcode."""
        return (self.flags >> 11) & 15

    @property
    def aa(self):
        """Return the authoritative-answer bit."""
        return bool(self.flags & 0x0400)

    @property
    def tc(self):
        """Return the truncation bit."""
        return bool(self.flags & 0x0200)

    @property
    def rd(self):
        """Return the recursion-desired bit."""
        return bool(self.flags & 0x0100)

    @property
    def ra(self):
        """Return the recursion-available bit."""
        return bool(self.flags & 0x0080)

    @property
    def rcode(self):
        """Return the four-bit DNS response code."""
        return self.flags & 15


def decode_name(data: bytes, offset: int, limit: int | None = None):
    """Decode one possibly compressed name from arbitrary DNS wire bytes."""
    padded = data if len(data) >= 12 else data + b"\0" * (12 - len(data))
    return parser.DNSMessage(padded).read_name(offset, limit)


def _record(record: parser.ResourceRecord) -> ResourceRecord:
    """Convert a parser record to the compatibility record representation."""
    # Convert supported textual values into their public compatibility forms.
    data: object = record.data
    if record.rrtype == TYPE_MX and not record.data.startswith("["):
        preference, target = record.data.split(" ", 1)
        data = (int(preference), target)
    elif (
        record.rrtype not in (TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_PTR, TYPE_MX)
        or record.data.startswith("[")
    ):
        data = record.raw_data

    # Preserve the common metadata for every converted record.
    return ResourceRecord(
        record.owner, record.rrtype, record.rrclass, record.ttl, data
    )


def parse_message(data: bytes) -> Message:
    """Parse wire bytes into the compatibility message representation."""
    # Decode the complete wire message with the bounds-checked parser.
    message_id, flags, questions, answers, authorities, additionals = (
        parser.parse_message(data)
    )

    # Convert each decoded section into immutable compatibility objects.
    return Message(
        message_id,
        flags,
        tuple(
            Question(item.name, item.qtype, item.qclass)
            for item in questions
        ),
        tuple(_record(item) for item in answers),
        tuple(_record(item) for item in authorities),
        tuple(_record(item) for item in additionals),
    )


def _name(value: str) -> bytes:
    """Encode one uncompressed fully qualified DNS name."""
    # Represent the root with its single terminating zero.
    if value == ".":
        return b"\0"

    # Prefix every label with its length and terminate the complete name.
    labels = (
        bytes((len(label),)) + label.encode("latin-1")
        for label in value.rstrip(".").split(".")
    )
    return b"".join(labels) + b"\0"


def _rdata(record: ResourceRecord) -> bytes:
    """Encode the assignment-supported RDATA forms for one record."""
    # Preserve opaque data for unknown or deliberately raw records.
    if isinstance(record.data, bytes):
        return record.data

    # Encode address and mail-exchanger records in their fixed wire forms.
    if record.rtype == TYPE_A:
        return bytes(int(part) for part in str(record.data).split("."))
    if record.rtype == TYPE_MX:
        preference, target = record.data
        return struct.pack("!H", preference) + _name(target)

    # The remaining supported types contain a single domain name.
    return _name(str(record.data))


def encode_message(
    message_id: int,
    questions=(),
    answers=(),
    authorities=(),
    additionals=(),
    *,
    qr=False,
    aa=False,
    rd=False,
    ra=False,
    rcode=0,
) -> bytes:
    """Encode a DNS message without compression for compatibility callers."""
    # Assemble the requested DNS header flags.
    flags = (
        (0x8000 if qr else 0)
        | (0x0400 if aa else 0)
        | (0x0100 if rd else 0)
        | (0x0080 if ra else 0)
        | rcode
    )

    # Write the header with counts derived from the supplied sections.
    out = bytearray(
        struct.pack(
            "!HHHHHH",
            message_id,
            flags,
            len(questions),
            len(answers),
            len(authorities),
            len(additionals),
        )
    )

    # Encode every question in its original order.
    for question in questions:
        out.extend(_name(question.name))
        out.extend(struct.pack("!HH", question.qtype, question.qclass))

    # Encode answer, authority, and additional resource records in order.
    for section in (answers, authorities, additionals):
        for record in section:
            rdata = _rdata(record)
            out.extend(_name(record.owner))
            out.extend(
                struct.pack(
                    "!HHIH",
                    record.rtype,
                    record.rclass,
                    record.ttl,
                    len(rdata),
                )
            )
            out.extend(rdata)
    return bytes(out)


def build_query(message_id: int, question: Question) -> bytes:
    """Build one non-recursive, single-question upstream DNS query."""
    return encode_message(message_id, (question,))


def build_response(
    query: Message,
    answers=(),
    authorities=(),
    additionals=(),
    *,
    aa=False,
    rcode=0,
) -> bytes:
    """Build a compressed client response or a safe oversized SERVFAIL."""
    # Assemble response flags while preserving the client's RD preference.
    flags = (
        0x8000
        | (0x0400 if aa else 0)
        | (0x0100 if query.rd else 0)
        | 0x0080
        | rcode
    )

    # Write the response header using the supplied section counts.
    out = bytearray(
        struct.pack(
            "!HHHHHH",
            query.message_id,
            flags,
            len(query.questions),
            len(answers),
            len(authorities),
            len(additionals),
        )
    )

    # Copy every client question into the response.
    for item in query.questions:
        out.extend(_name(item.name))
        out.extend(struct.pack("!HH", item.qtype, item.qclass))

    # Enable a question-name pointer only for an unambiguous single question.
    question_name = (
        normalize_name(query.questions[0].name)
        if len(query.questions) == 1
        else None
    )

    # Encode all resource sections, compressing matching record owners.
    for section in (answers, authorities, additionals):
        for record in section:
            owner = (
                b"\xc0\x0c"
                if question_name
                and normalize_name(record.owner) == question_name
                else _name(record.owner)
            )
            out.extend(owner)
            rdata = _rdata(record)
            out.extend(
                struct.pack(
                    "!HHIH",
                    record.rtype,
                    record.rclass,
                    record.ttl,
                    len(rdata),
                )
            )
            out.extend(rdata)

    # Return valid UDP-sized output or replace it with a compact SERVFAIL.
    packet = bytes(out)
    if len(packet) <= 512:
        return packet
    return encode_message(
        query.message_id,
        query.questions,
        qr=True,
        rd=query.rd,
        ra=True,
        rcode=2,
    )


def format_message(message: Message) -> str:
    """Format a parsed compatibility message for readable test diagnostics."""
    # Format header flags and section counts first.
    lines = [
        f"ID: {message.message_id}",
        "--- FLAGS ---",
        f"QR: {message.qr}",
        f"Opcode: {message.opcode}",
        f"AA: {message.aa}",
        f"TC: {message.tc}",
        f"RD: {message.rd}",
        f"RA: {message.ra}",
        f"RCODE: {message.rcode}",
        "--- COUNTS ---",
        f"Questions: {len(message.questions)}",
        f"Answers: {len(message.answers)}",
        f"Authority: {len(message.authorities)}",
        f"Additional: {len(message.additionals)}",
    ]
    sections = (
        ("QUESTIONS", message.questions),
        ("ANSWERS", message.answers),
        ("AUTHORITY", message.authorities),
        ("ADDITIONAL", message.additionals),
    )
    names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}

    # Format questions and records according to their public data shape.
    for title, records in sections:
        lines.append(f"--- {title} ---")
        for item in records:
            if isinstance(item, Question):
                kind = names.get(item.qtype, f"TYPE{item.qtype}")
                lines.append(f"{item.name} IN {kind}")
            elif isinstance(item.data, bytes):
                details = (
                    f"MALFORMED_RDATA RDLENGTH {len(item.data)}"
                    if item.rtype in names
                    else f"RDLENGTH {len(item.data)}"
                )
                lines.append(
                    f"{item.owner} {item.ttl} TYPE{item.rtype} {details}"
                )
            else:
                lines.append(
                    f"{item.owner} {item.ttl} TYPE{item.rtype} {item.data}"
                )
    return "\n".join(lines)
