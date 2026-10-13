"""Small independent UDP DNS server used by resolver integration tests."""

import socket
import struct
import threading

from tests.wire_helpers import message


def read_query(packet):
    if len(packet) < 17:
        raise ValueError("short query")
    message_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    if (qdcount, ancount, nscount, arcount) != (1, 0, 0, 0):
        raise ValueError("unexpected query counts")
    labels = []
    offset = 12
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("test server expects uncompressed queries")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    offset += 4
    if offset != len(packet):
        raise ValueError("unexpected query data")
    name = "." if not labels else ".".join(labels) + "."
    return {
        "id": message_id,
        "flags": flags,
        "name": name,
        "type": qtype,
        "class": qclass,
        "question_wire": packet[12:offset],
    }


def make_response(
    query_packet,
    *,
    flags=0x8000,
    answers=(),
    authorities=(),
    additionals=(),
    message_id=None,
    question_wire=None,
):
    query = read_query(query_packet)
    response_id = query["id"] if message_id is None else message_id
    response_question = (
        query["question_wire"] if question_wire is None else question_wire
    )
    return message(
        message_id=response_id,
        flags=flags,
        questions=(response_question,),
        answers=answers,
        authorities=authorities,
        additionals=additionals,
    )


class ScriptedDNSServer:
    def __init__(self, address, port, callback):
        self.address = address
        self.port = port
        self.callback = callback
        self.queries = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((address, port))
        self._socket.settimeout(0.05)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                packet, client = self._socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self.queries.append(read_query(packet))
            threading.Thread(
                target=self._respond,
                args=(packet, client),
                daemon=True,
            ).start()

    def _respond(self, packet, client):
        responses = self.callback(packet)
        if responses is None:
            return
        if isinstance(responses, bytes):
            responses = (responses,)
        for response in responses:
            try:
                self._socket.sendto(response, client)
            except OSError:
                return

    def query_count(self):
        with self._lock:
            return len(self.queries)

    def stop(self):
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=1)


def free_udp_port(address="127.0.0.1"):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((address, 0))
        return probe.getsockname()[1]
    finally:
        probe.close()
