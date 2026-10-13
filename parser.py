#!/usr/bin/env python3
"""Print a human-readable representation of one DNS wire-format message.

This program intentionally uses only the Python standard library.  It is a
decoder, not a resolver: it reads a single message from a file and exits.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final


class DNSParseError(ValueError):
    """Raised when a DNS message cannot be decoded safely."""


TYPE_NAMES: Final = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}
CLASS_NAMES: Final = {1: "IN"}
RCODE_NAMES: Final = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
MAX_POINTER_JUMPS: Final = 20


def type_name(value: int) -> str:
    """Return a stable display name for a DNS record type."""
    return TYPE_NAMES.get(value, f"TYPE{value}")


def class_name(value: int) -> str:
    """Return a stable display name for a DNS record class."""
    return CLASS_NAMES.get(value, f"CLASS{value}")


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class ResourceRecord:
    owner: str
    rrtype: int
    rrclass: int
    ttl: int
    rdlength: int
    data: str
    raw_data: bytes = b""


class DNSMessage:
    """A bounds-checked DNS wire-message reader."""

    def __init__(self, data: bytes) -> None:
        """Initialise a bounded reader for one complete DNS wire message."""
        self.data = data
        if len(data) < 12:
            raise DNSParseError(
                "message is shorter than the 12-byte DNS header"
            )

    def u16(self, offset: int) -> int:
        """Read one network-order unsigned 16-bit integer at an offset."""
        self._require(offset, 2)
        return int.from_bytes(self.data[offset : offset + 2], "big")

    def u32(self, offset: int) -> int:
        """Read one network-order unsigned 32-bit integer at an offset."""
        self._require(offset, 4)
        return int.from_bytes(self.data[offset : offset + 4], "big")

    def _require(
        self, offset: int, size: int, limit: int | None = None
    ) -> None:
        """Raise an error when a byte range is outside its message boundary."""
        end = offset + size
        boundary = len(self.data) if limit is None else limit
        if offset < 0 or end > boundary or end > len(self.data):
            raise DNSParseError("unexpected end of message")

    def read_name(
        self, offset: int, limit: int | None = None
    ) -> tuple[str, int]:
        """Decode a possibly compressed domain name at *offset*.

        ``limit`` constrains bytes belonging to the original field (not pointer
        targets), which is essential when names occur inside RDATA.
        """
        # Establish the field boundary before following any compression pointer.
        if limit is None:
            limit = len(self.data)
        self._require(offset, 1, limit)

        # Track decoded labels, pointer state, and DNS safety limits.
        labels: list[str] = []
        position = offset
        next_offset: int | None = None
        followed_pointer = False
        seen_positions: set[int] = set()
        pointer_jumps = 0
        encoded_length = 1  # terminating zero, plus label length octets

        # Consume labels and pointers until the terminating root label.
        while True:
            current_limit = len(self.data) if followed_pointer else limit
            self._require(position, 1, current_limit)
            if position in seen_positions:
                raise DNSParseError("compression pointer loop in domain name")
            seen_positions.add(position)

            first = self.data[position]
            label_kind = first & 0xC0

            # Finish the field while retaining the caller's resume offset.
            if first == 0:
                if next_offset is None:
                    next_offset = position + 1
                return (".".join(labels) + ".") if labels else ".", next_offset

            # Decode an ordinary label without crossing its current boundary.
            if label_kind == 0x00:
                length = first
                if length > 63:
                    raise DNSParseError("domain-name label exceeds 63 bytes")
                self._require(position + 1, length, current_limit)
                encoded_length += length + 1
                if encoded_length > 255:
                    raise DNSParseError("decoded domain name exceeds 255 bytes")
                raw_label = self.data[position + 1 : position + 1 + length]
                labels.append(raw_label.decode("latin-1"))
                position += length + 1
                continue

            # Follow a valid compression pointer with loop and depth checks.
            if label_kind == 0xC0:
                self._require(position, 2, current_limit)
                target = ((first & 0x3F) << 8) | self.data[position + 1]
                if target >= len(self.data):
                    raise DNSParseError(
                        "compression pointer targets outside message"
                    )
                pointer_jumps += 1
                if pointer_jumps > MAX_POINTER_JUMPS:
                    raise DNSParseError(
                        "domain name has more than 20 compression jumps"
                    )
                if next_offset is None:
                    next_offset = position + 2
                position = target
                followed_pointer = True
                continue

            raise DNSParseError("reserved domain-name label form")

    def read_question(self, offset: int) -> tuple[Question, int]:
        """Decode one Question section entry and return its next offset."""
        # Read the variable-length name before the fixed type and class.
        name, offset = self.read_name(offset)
        self._require(offset, 4)
        return (
            Question(name, self.u16(offset), self.u16(offset + 2)),
            offset + 4,
        )

    def read_record(self, offset: int) -> tuple[ResourceRecord, int]:
        """Decode one resource record and return the next record offset."""
        # Decode the owner followed by the fixed resource-record header.
        owner, offset = self.read_name(offset)
        self._require(offset, 10)
        rrtype = self.u16(offset)
        rrclass = self.u16(offset + 2)
        ttl = self.u32(offset + 4)
        rdlength = self.u16(offset + 8)
        rdata_start = offset + 10
        rdata_end = rdata_start + rdlength
        self._require(rdata_start, rdlength)

        # Decode RDATA within its declared boundary and retain its raw bytes.
        record = ResourceRecord(
            owner=owner,
            rrtype=rrtype,
            rrclass=rrclass,
            ttl=ttl,
            rdlength=rdlength,
            data=self._decode_rdata(rrtype, rdata_start, rdata_end),
            raw_data=self.data[rdata_start:rdata_end],
        )
        return record, rdata_end

    def _decode_rdata(self, rrtype: int, start: int, end: int) -> str:
        """Decode only the supported RDATA forms, without crossing RDLENGTH."""
        try:
            # Decode an IPv4 address only when it has the required four octets.
            if rrtype == 1:  # A
                if end - start != 4:
                    raise DNSParseError("A RDATA must be exactly four bytes")
                return ".".join(str(octet) for octet in self.data[start:end])

            # Decode the supported single-name record types.
            if rrtype in (2, 5, 12):  # NS, CNAME, PTR
                name, next_offset = self.read_name(start, end)
                if next_offset != end:
                    raise DNSParseError("name RDATA does not end at RDLENGTH")
                return name

            # Decode an MX preference followed by its exchange name.
            if rrtype == 15:  # MX
                self._require(start, 2, end)
                preference = self.u16(start)
                name, next_offset = self.read_name(start + 2, end)
                if next_offset != end:
                    raise DNSParseError("MX RDATA does not end at RDLENGTH")
                return f"{preference} {name}"
        except DNSParseError:
            # A malformed known RDATA must not disturb traversal of later RRs.
            return f"[malformed RDATA; RDLENGTH {end - start}]"

        # Retain a stable description for unsupported record types.
        return f"RDLENGTH {end - start}"


def parse_message(
    data: bytes,
) -> tuple[
    int,
    int,
    list[Question],
    list[ResourceRecord],
    list[ResourceRecord],
    list[ResourceRecord],
]:
    """Parse one complete DNS message into its header and three RR sections."""
    # Read the fixed header and its four section counts.
    message = DNSMessage(data)
    message_id = message.u16(0)
    flags = message.u16(2)
    counts: list[int] = []
    for header_offset in (4, 6, 8, 10):
        counts.append(message.u16(header_offset))
    offset = 12

    # Read all question records in their wire order.
    questions: list[Question] = []
    for _ in range(counts[0]):
        question, offset = message.read_question(offset)
        questions.append(question)

    # Read answer, authority, and additional resource-record sections.
    sections: list[list[ResourceRecord]] = []
    for count in counts[1:]:
        records: list[ResourceRecord] = []
        for _ in range(count):
            record, offset = message.read_record(offset)
            records.append(record)
        sections.append(records)

    # Reject bytes not accounted for by the declared section counts.
    if offset != len(data):
        raise DNSParseError("trailing bytes after DNS sections")

    return message_id, flags, questions, sections[0], sections[1], sections[2]


def print_record(record: ResourceRecord) -> None:
    """Print one resource record in the parser's stable display format."""
    print(
        f"{record.owner} {record.ttl} {class_name(record.rrclass)} "
        f"{type_name(record.rrtype)} {record.data}"
    )


def print_message(data: bytes) -> None:
    """Parse and print a human-readable DNS message."""
    # Parse the packet once before emitting any output.
    message_id, flags, questions, answers, authority, additional = (
        parse_message(data)
    )
    qdcount = len(questions)

    # Print header flags and actual parsed section counts.
    print(f"ID: {message_id}")
    print("--- FLAGS ---")
    print(f"QR: {bool(flags & 0x8000)}")
    print(f"Opcode: {(flags >> 11) & 0x0F}")
    print(f"AA: {bool(flags & 0x0400)}")
    print(f"TC: {bool(flags & 0x0200)}")
    print(f"RD: {bool(flags & 0x0100)}")
    print(f"RA: {bool(flags & 0x0080)}")
    rcode = flags & 0x000F
    print(f"RCODE: {RCODE_NAMES.get(rcode, f'RCODE{rcode}')}")
    print("--- COUNTS ---")
    print(f"Questions: {qdcount}")
    print(f"Answers: {len(answers)}")
    print(f"Authority: {len(authority)}")
    print(f"Additional: {len(additional)}")

    # Print each question in its original order.
    print("--- QUESTIONS ---")
    for question in questions:
        print(
            f"{question.name} {class_name(question.qclass)} "
            f"{type_name(question.qtype)}"
        )

    # Print all three resource-record sections in wire order.
    print("--- ANSWERS ---")
    for record in answers:
        print_record(record)
    print("--- AUTHORITY ---")
    for record in authority:
        print_record(record)
    print("--- ADDITIONAL ---")
    for record in additional:
        print_record(record)


def main(argv: list[str]) -> int:
    """Run the parser command-line interface and return its exit status."""
    # Validate the single required message-file argument.
    if len(argv) != 2:
        print(f"Usage: {Path(argv[0]).name} message_file", file=sys.stderr)
        return 2

    # Parse and display the file while converting expected failures to status 1.
    try:
        print_message(Path(argv[1]).read_bytes())
    except (OSError, DNSParseError) as error:
        print(f"Error: malformed DNS message: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
