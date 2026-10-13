"""Independent DNS byte helpers used only by the test suite."""

import struct


def wire_name(name):
    if name == ".":
        return b"\x00"
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def question(name, qtype=1, qclass=1):
    return wire_name(name) + struct.pack("!HH", qtype, qclass)


def record(owner, rtype, rdata, ttl=60, rclass=1, owner_wire=None):
    owner_bytes = wire_name(owner) if owner_wire is None else owner_wire
    return (
        owner_bytes
        + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        + rdata
    )


def message(
    message_id=0x1234,
    flags=0x0100,
    questions=(),
    answers=(),
    authorities=(),
    additionals=(),
):
    return (
        struct.pack(
            "!HHHHHH",
            message_id,
            flags,
            len(questions),
            len(answers),
            len(authorities),
            len(additionals),
        )
        + b"".join(questions)
        + b"".join(answers)
        + b"".join(authorities)
        + b"".join(additionals)
    )
