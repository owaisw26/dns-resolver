"""DNS wire helpers for black-box CLI tests; they never import project code."""

from __future__ import annotations

import struct


def wire_name(value: str) -> bytes:
    """Encode an absolute DNS name without compression."""
    if value == ".":
        return b"\0"
    labels = value.rstrip(".").split(".")
    return b"".join(
        bytes((len(label),)) + label.encode("ascii") for label in labels
    ) + b"\0"


def question(name: str, qtype: int, qclass: int = 1) -> bytes:
    """Build one DNS Question section entry."""
    return wire_name(name) + struct.pack("!HH", qtype, qclass)


def message(
    message_id: int,
    flags: int,
    questions: tuple[bytes, ...],
    answers: tuple[bytes, ...] = (),
    authority: tuple[bytes, ...] = (),
    additional: tuple[bytes, ...] = (),
) -> bytes:
    """Build a complete DNS message from already encoded sections."""
    header = struct.pack(
        "!HHHHHH",
        message_id,
        flags,
        len(questions),
        len(answers),
        len(authority),
        len(additional),
    )
    return header + b"".join(questions + answers + authority + additional)


def query(message_id: int, name: str, qtype: int, flags: int = 0x0100) -> bytes:
    """Build one single-question client query."""
    return message(message_id, flags, (question(name, qtype),))


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode one DNS name for independent response assertions."""
    labels: list[str] = []
    next_offset = None
    seen: set[int] = set()
    while True:
        if offset in seen or offset >= len(data):
            raise ValueError("invalid DNS name")
        seen.add(offset)
        length = data[offset]
        if length == 0:
            result = ".".join(labels) + "." if labels else "."
            return result, next_offset or offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0 or offset + length >= len(data):
            raise ValueError("invalid label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("latin-1"))
        offset += length + 1


def decode_response(data: bytes) -> dict:
    """Decode enough DNS response fields to verify observable behaviour."""
    message_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = read_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append((name, qtype, qclass))
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            owner, offset = read_name(data, offset)
            rtype, rclass, ttl, length = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10
            rdata = data[offset : offset + length]
            offset += length
            if rtype == 1 and len(rdata) == 4:
                value = ".".join(str(part) for part in rdata)
            elif rtype in (2, 5, 12):
                value, _ = read_name(data, offset - length)
            elif rtype == 15 and len(rdata) >= 3:
                preference = struct.unpack("!H", rdata[:2])[0]
                target, _ = read_name(data, offset - length + 2)
                value = (preference, target)
            else:
                value = rdata
            records.append((owner, rtype, rclass, ttl, value))
        sections.append(records)
    if offset != len(data):
        raise ValueError("trailing response bytes")
    return {
        "id": message_id,
        "flags": flags,
        "questions": questions,
        "answers": sections[0],
        "authority": sections[1],
        "additional": sections[2],
    }
