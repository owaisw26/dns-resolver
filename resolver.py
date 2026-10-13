#!/usr/bin/env python3
"""An iterative UDP-only DNS resolver for COMP3331 assignment stages 2 and 3."""

from __future__ import annotations

import secrets
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import parser


TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_PTR, TYPE_MX = 1, 2, 5, 12, 15
CLASS_IN = 1
SUPPORTED_TYPES = {TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_PTR, TYPE_MX}
MAX_UDP_DNS_MESSAGE = 512
# Test hooks may redirect an upstream IP to a local ephemeral endpoint.  Normal
# operation leaves this empty and always uses the DNS UDP port (53).
UPSTREAM_ENDPOINTS: dict[str, tuple[str, int]] = {}


@dataclass(frozen=True)
class DNSRecord:
    owner: str
    ttl: int
    rrtype: int
    rrclass: int
    data: str


@dataclass
class Budget:
    deadline: float
    attempts: int = 0
    referrals: int = 0
    cname_count: int = 0


@dataclass(frozen=True)
class Resolution:
    rcode: int
    answers: list[DNSRecord]
    direct_authoritative: bool = False


class RootHints(list[DNSRecord]):
    """Parsed hints plus small mapping-style access used by local test tools."""

    def __getitem__(self, key):
        """Support list access plus named views used by test helpers."""
        # Build the named root-record views requested by compatibility tests.
        if isinstance(key, str):
            ns: list[DNSRecord] = []
            addresses: list[DNSRecord] = []
            for record in self:
                if record.rrtype == TYPE_NS and norm(record.owner) == ".":
                    ns.append(record)
                if record.rrtype == TYPE_A:
                    addresses.append(record)
            if key == "ns":
                return ns
            if key == "addresses":
                return addresses
            if key == "root_ips":
                # Match root nameservers to their corresponding A records.
                root_ips: list[str] = []
                for nameserver in ns:
                    for address in addresses:
                        if norm(address.owner) == norm(nameserver.data):
                            root_ips.append(address.data)
                return tuple(root_ips)
            raise KeyError(key)
        return super().__getitem__(key)


def norm(name: str) -> str:
    """Return a fully qualified, case-insensitive DNS comparison key."""
    return name.lower() if name.endswith(".") else name.lower() + "."


def name_labels(name: str) -> tuple[str, ...]:
    """Return normalised labels for DNS hierarchy comparisons."""
    normalised = norm(name)
    if normalised == ".":
        return ()
    return tuple(normalised[:-1].split("."))


def is_relevant_referral(
    referral_zone: str,
    current_name: str,
    current_zone: str,
) -> bool:
    """Return whether a referral moves down the hierarchy for this lookup."""
    referral = name_labels(referral_zone)
    qname = name_labels(current_name)
    parent = name_labels(current_zone)
    return (
        len(referral) > len(parent)
        and qname[-len(referral):] == referral
        and (not parent or referral[-len(parent):] == parent)
    )


def parse_root_hints(path: str) -> RootHints:
    """Read the assignment's supported NS/A root-hints subset."""
    records: RootHints = RootHints()
    current_ttl = 0

    # Read meaningful fields from each non-empty, uncommented line.
    for raw in Path(path).read_text(encoding="ascii").splitlines():
        fields = raw.split(";", 1)[0].split()
        if not fields:
            continue
        if fields[0].upper() == "$TTL":
            current_ttl = int(fields[1])
            continue
        if fields[0].startswith("$") or len(fields) < 3:
            continue

        # Locate the supported record type within the flexible zone format.
        type_index = None
        for index in range(1, len(fields)):
            if fields[index].upper() in ("A", "NS"):
                type_index = index
                break
        if type_index is None or type_index + 1 == len(fields):
            continue

        # Apply either the record TTL or the latest $TTL default.
        ttl = current_ttl
        for value in fields[1:type_index]:
            if value.upper() != "IN":
                ttl = int(value)

        # Preserve the file order when storing supported hints.
        rrtype = TYPE_A if fields[type_index].upper() == "A" else TYPE_NS
        records.append(
            DNSRecord(fields[0], ttl, rrtype, CLASS_IN, fields[type_index + 1])
        )
    return records


class Encoder:
    """Encode DNS questions and records with safe name compression."""
    def __init__(self) -> None:
        """Create an empty encoder and compression-offset table."""
        self.data = bytearray()
        self.offsets: dict[str, int] = {}

    def u16(self, value: int) -> None:
        """Append one network-order unsigned 16-bit integer."""
        self.data.extend(struct.pack("!H", value))

    def u32(self, value: int) -> None:
        """Append one network-order unsigned 32-bit integer."""
        self.data.extend(struct.pack("!I", value))

    def name(self, value: str) -> None:
        """Append a DNS name with case-insensitive suffix compression."""
        # Preserve the first wire spelling while normalising compression keys.
        value = value if value.endswith(".") else value + "."

        # Encode the root directly or reuse its previous compression offset.
        if value == ".":
            if "." in self.offsets:
                self.u16(0xC000 | self.offsets["."])
            else:
                self.offsets["."] = len(self.data)
                self.data.append(0)
            return

        # Encode labels until an already-written suffix can be referenced.
        labels = value[:-1].split(".")
        for i, label in enumerate(labels):
            suffix = ".".join(labels[i:]) + "."
            key = norm(suffix)
            if key in self.offsets and self.offsets[key] < 0x4000:
                self.u16(0xC000 | self.offsets[key])
                return
            raw = label.encode("latin-1")
            if not 0 < len(raw) <= 63:
                raise ValueError("invalid DNS name")
            self.offsets[key] = len(self.data)
            self.data.append(len(raw))
            self.data.extend(raw)

        # Terminate an uncompressed name and remember the root position.
        self.offsets.setdefault(".", len(self.data))
        self.data.append(0)

    def question(self, question: parser.Question) -> None:
        """Append one DNS Question section entry."""
        self.name(question.name)
        self.u16(question.qtype)
        self.u16(question.qclass)

    def record(self, record: DNSRecord) -> None:
        """Append one supported DNS resource record."""
        # Encode the fixed resource-record fields and reserve RDLENGTH.
        self.name(record.owner)
        self.u16(record.rrtype)
        self.u16(record.rrclass)
        self.u32(record.ttl)
        length_at = len(self.data)
        self.u16(0)
        start = len(self.data)

        # Encode the type-specific record data.
        if record.rrtype == TYPE_A:
            self.data.extend(
                bytes(int(part) for part in record.data.split("."))
            )
        elif record.rrtype == TYPE_MX:
            preference, target = record.data.split(" ", 1)
            self.u16(int(preference))
            self.name(target)
        else:  # NS, CNAME and PTR are the supported name-valued record types.
            self.name(record.data)

        # Fill the reserved length after the encoded size is known.
        self.data[length_at : length_at + 2] = struct.pack(
            "!H", len(self.data) - start
        )


class Resolver:
    def __init__(self, root_hints_file: str, timeout: int) -> None:
        """Load root hints and initialise the shared TTL cache."""
        self.hints = parse_root_hints(root_hints_file)
        self.timeout = timeout
        self.cache: dict[
            tuple[str, int, int], list[tuple[DNSRecord, float]]
        ] = {}
        self.cache_lock = threading.Lock()

    def root_local(self, question: parser.Question) -> list[DNSRecord] | None:
        """Return a Stage 2 root-hints-local answer when one exists."""
        # Separate root NS records from the available address records.
        roots: list[DNSRecord] = []
        addresses: list[DNSRecord] = []
        for record in self.hints:
            if record.rrtype == TYPE_NS and norm(record.owner) == ".":
                roots.append(record)
            if record.rrtype == TYPE_A:
                addresses.append(record)

        # Reject non-IN questions before checking local record types.
        if question.qclass != CLASS_IN:
            return None

        # Return root nameservers together with their matching glue.
        if question.qtype == TYPE_NS and norm(question.name) == ".":
            extra: list[DNSRecord] = []
            for nameserver in roots:
                for address in addresses:
                    if norm(address.owner) == norm(nameserver.data):
                        extra.append(address)
            return roots + extra  # caller separates NS answers from glue below

        # Match root-hints addresses case-insensitively.
        if question.qtype == TYPE_A:
            matched: list[DNSRecord] = []
            for address in addresses:
                if norm(address.owner) == norm(question.name):
                    matched.append(address)
            return matched if matched else None
        return None

    def cache_records(self, records: list[DNSRecord]) -> None:
        """Replace cached RRsets with positive records and fresh expiries."""
        now = time.monotonic()
        grouped: dict[
            tuple[str, int, int], list[tuple[DNSRecord, float]]
        ] = {}

        # Group cacheable records into complete RRsets with absolute expiries.
        for record in records:
            if record.ttl <= 0:
                continue
            key = (norm(record.owner), record.rrtype, record.rrclass)
            grouped.setdefault(key, []).append((record, now + record.ttl))

        # Replace each RRset atomically under the shared cache lock.
        with self.cache_lock:
            for key, entries in grouped.items():
                self.cache[key] = entries

    def cached(self, question: parser.Question) -> list[DNSRecord] | None:
        """Recreate a complete unexpired answer and CNAME chain from cache."""
        now = time.monotonic()

        def records_for(name: str, rrtype: int) -> list[DNSRecord]:
            """Return one unexpired cached RRset with adjusted TTLs."""
            # Remove expired entries while holding the cache lock.
            key = (norm(name), rrtype, question.qclass)
            with self.cache_lock:
                kept: list[tuple[DNSRecord, float]] = []
                remaining_ttls: list[int] = []
                for record, expiry in self.cache.get(key, []):
                    remaining = int(expiry - now)
                    if remaining > 0:
                        kept.append((record, expiry))
                        remaining_ttls.append(remaining)
                if kept:
                    self.cache[key] = kept
                else:
                    self.cache.pop(key, None)

            # Copy live records with their current whole-second TTLs.
            records: list[DNSRecord] = []
            for (record, _), remaining in zip(kept, remaining_ttls):
                records.append(
                    DNSRecord(
                        record.owner,
                        remaining,
                        record.rrtype,
                        record.rrclass,
                        record.data,
                    )
                )
            return records

        # A direct CNAME question returns the alias RRset without chasing it.
        if question.qtype == TYPE_CNAME:
            aliases = records_for(question.name, TYPE_CNAME)
            if not aliases or len(aliases) > 10:
                return None
            target = norm(aliases[0].data)
            if any(norm(alias.data) != target for alias in aliases):
                return None
            return aliases

        # Follow a cached CNAME chain until the requested RRset is complete.
        chain: list[DNSRecord] = []
        current = question.name
        seen = {norm(current)}
        for cname_count in range(11):
            final = records_for(current, question.qtype)
            if final:
                return chain + final
            if cname_count == 10:
                return None
            aliases = records_for(current, TYPE_CNAME)
            if not aliases:
                return None

            # Reject inconsistent RRsets and alias loops.
            target = norm(aliases[0].data)
            if any(norm(alias.data) != target for alias in aliases):
                return None
            if len(chain) + len(aliases) > 10:
                return None
            if target in seen:
                return None
            chain.extend(aliases)
            current = aliases[0].data
            seen.add(target)
        return None

    def upstream_query(
        self,
        server_ip: str,
        question: parser.Question,
        budget: Budget,
    ) -> tuple[
        int,
        list[DNSRecord],
        list[DNSRecord],
        list[DNSRecord],
    ] | None:
        """Send one iterative query and validate a matching UDP response."""
        # Enforce the resolution-wide attempt and elapsed-time limits.
        if budget.attempts >= 50 or time.monotonic() >= budget.deadline:
            return None
        budget.attempts += 1

        # Build a fresh non-recursive query with an unpredictable ID.
        transaction_id = secrets.randbits(16)
        query = struct.pack("!HHHHHH", transaction_id, 0, 1, 0, 0, 0)
        encoder = Encoder()
        encoder.data.extend(query)
        encoder.question(question)

        # Limit this attempt to both the configured timeout and global budget.
        wait = min(self.timeout, max(0.0, budget.deadline - time.monotonic()))
        if wait <= 0:
            return None
        endpoint = UPSTREAM_ENDPOINTS.get(server_ip, (server_ip, 53))
        attempt_deadline = time.monotonic() + wait
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(wait)
                sock.sendto(bytes(encoder.data), endpoint)

                # Ignore unrelated datagrams but fail this candidate promptly.
                while True:
                    remaining = attempt_deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    sock.settimeout(remaining)
                    data, source = sock.recvfrom(65535)
                    action, response = self._validate_upstream_datagram(
                        data, source, endpoint, transaction_id, question
                    )
                    if action == "ignore":
                        continue
                    return response
        except (socket.timeout, OSError):
            return None

    def _validate_upstream_datagram(
        self,
        data: bytes,
        source: tuple[str, int],
        endpoint: tuple[str, int],
        transaction_id: int,
        question: parser.Question,
    ) -> tuple[
        str,
        tuple[
            int,
            list[DNSRecord],
            list[DNSRecord],
            list[DNSRecord],
        ] | None,
    ]:
        """Classify one upstream datagram as unrelated, failed, or accepted."""
        # A datagram from another endpoint cannot belong to this candidate.
        if source != endpoint:
            return "ignore", None

        # Match cheap header fields before deciding whether parse failure matters.
        if len(data) < 4:
            return "fail", None
        response_id, flags = struct.unpack_from("!HH", data)
        if response_id != transaction_id or ((flags >> 11) & 15) != 0:
            return "ignore", None

        # A structurally malformed response from the matching candidate fails it.
        try:
            (
                _,
                flags,
                questions,
                answers,
                authority,
                additional,
            ) = parser.parse_message(data)
        except parser.DNSParseError:
            return "fail", None

        # Ignore a well-formed datagram for a different Question.
        matching_question = (
            len(questions) == 1
            and norm(questions[0].name) == norm(question.name)
            and questions[0].qtype == question.qtype
            and questions[0].qclass == question.qclass
        )
        if not matching_question:
            return "ignore", None

        # Matching invalid flags, malformed RDATA, and failure RCODEs fail fast.
        if not flags & 0x8000 or flags & 0x0200 or flags & 15 not in (0, 3):
            return "fail", None
        records = answers + authority + additional
        if any(
            record.rrtype in SUPPORTED_TYPES and record.data.startswith("[")
            for record in records
        ):
            return "fail", None
        return "accept", (
            flags,
            self._records(answers),
            self._records(authority),
            self._records(additional),
        )

    @staticmethod
    def _records(records: list[parser.ResourceRecord]) -> list[DNSRecord]:
        """Convert supported, well-formed parsed records to resolver records."""
        converted: list[DNSRecord] = []

        # Discard record types the resolver cannot safely return or follow.
        for record in records:
            if (
                record.rrtype in SUPPORTED_TYPES
                and not record.data.startswith("[")
            ):
                converted.append(
                    DNSRecord(
                        record.owner,
                        record.ttl,
                        record.rrtype,
                        record.rrclass,
                        record.data,
                    )
                )
        return converted

    def _root_candidates(self) -> list[str]:
        """Return root-server addresses in root-hints nameserver order."""
        # Separate root NS records from all address records.
        root_ns: list[DNSRecord] = []
        root_a: list[DNSRecord] = []
        for record in self.hints:
            if record.rrtype == TYPE_NS and norm(record.owner) == ".":
                root_ns.append(record)
            if record.rrtype == TYPE_A:
                root_a.append(record)

        # Match each root nameserver to its address records.
        candidates: list[str] = []
        for nameserver in root_ns:
            for address in root_a:
                if norm(address.owner) == norm(nameserver.data):
                    candidates.append(address.data)
        return candidates

    @staticmethod
    def _matching_answers(
        answers: list[DNSRecord],
        name: str,
        rrclass: int,
    ) -> list[DNSRecord]:
        """Return answer records owned by the current name and class."""
        # DNS names compare case-insensitively.
        return [
            record
            for record in answers
            if norm(record.owner) == norm(name) and record.rrclass == rrclass
        ]

    def _follow_answer_chain(
        self,
        question: parser.Question,
        current: str,
        chain: list[DNSRecord],
        answers: list[DNSRecord],
        authoritative: bool,
        budget: Budget,
    ) -> tuple[Resolution | None, str | None, bool]:
        """Use direct answers and in-packet CNAMEs from one response.

        The returned target requests a restart from the root.  The final boolean
        identifies a CNAME loop or overlong chain, which must fail resolution.
        """
        # Check records that directly belong to the current lookup name.
        matching = self._matching_answers(
            answers, current, question.qclass
        )
        if question.qtype == TYPE_CNAME:
            direct = [
                record for record in matching if record.rrtype == TYPE_CNAME
            ]
            if direct:
                _, failed = self._retain_aliases(direct, chain, budget)
                if failed:
                    return None, None, True
                return Resolution(0, list(chain), authoritative), None, False

        requested = [
            record for record in matching if record.rrtype == question.qtype
        ]
        if requested:
            return (
                Resolution(0, chain + requested, authoritative and not chain),
                None,
                False,
            )

        # Follow every usable CNAME link already present in this packet.
        aliases = [
            record for record in matching if record.rrtype == TYPE_CNAME
        ]
        if not aliases:
            return None, None, False
        chain_before_response = len(chain)
        while aliases:
            current, failed = self._retain_aliases(aliases, chain, budget)
            if failed:
                return None, None, True

            # Inspect the retained RRset's target records in the same packet.
            matching = self._matching_answers(
                answers, current, question.qclass
            )
            requested = [
                record
                for record in matching
                if record.rrtype == question.qtype
            ]
            if requested:
                return (
                    Resolution(
                        0,
                        chain + requested,
                        authoritative and chain_before_response == 0,
                    ),
                    None,
                    False,
                )
            aliases = [
                record for record in matching if record.rrtype == TYPE_CNAME
            ]

        # The packet ended at an alias target, so restart there from the root.
        return None, current, False

    @staticmethod
    def _retain_aliases(
        aliases: list[DNSRecord],
        chain: list[DNSRecord],
        budget: Budget,
    ) -> tuple[str | None, bool]:
        """Retain one consistent CNAME RRset or identify a fatal chain."""
        # Every record in a CNAME RRset must name the same target.
        target = norm(aliases[0].data)
        if any(norm(alias.data) != target for alias in aliases):
            return None, True

        # Count retained records, and reject self-links and earlier chain owners.
        previous_owners = {norm(record.owner) for record in chain}
        previous_owners.add(norm(aliases[0].owner))
        if (
            budget.cname_count + len(aliases) > 10
            or target in previous_owners
        ):
            return None, True
        chain.extend(aliases)
        budget.cname_count += len(aliases)
        return aliases[0].data, False

    def _retain_negative_aliases(
        self,
        current: str,
        chain: list[DNSRecord],
        answers: list[DNSRecord],
        rrclass: int,
        budget: Budget,
    ) -> bool:
        """Retain a same-packet CNAME chain from an NXDOMAIN response."""
        # Follow only answer-section aliases reachable from the current name.
        while True:
            matching = self._matching_answers(answers, current, rrclass)
            aliases = [
                record
                for record in matching
                if record.rrtype == TYPE_CNAME
            ]
            if not aliases:
                return True
            current, failed = self._retain_aliases(aliases, chain, budget)
            if failed:
                return False

    @staticmethod
    def _referred_nameservers(
        authority: list[DNSRecord],
        current: str,
        current_zone: str,
    ) -> tuple[str | None, list[DNSRecord]]:
        """Return the first relevant referral zone and its NS RRset."""
        # Select the first NS record that moves down the queried DNS branch.
        referral_zone = next(
            (
                record.owner
                for record in authority
                if record.rrtype == TYPE_NS
                and record.rrclass == CLASS_IN
                and is_relevant_referral(
                    record.owner, current, current_zone
                )
            ),
            None,
        )
        if referral_zone is None:
            return None, []

        # Collect the complete nameserver RRset for the selected zone.
        referred = [
            record
            for record in authority
            if record.rrtype == TYPE_NS
            and record.rrclass == CLASS_IN
            and norm(record.owner) == norm(referral_zone)
        ]
        return referral_zone, referred

    def _referral_candidates(
        self,
        referred: list[DNSRecord],
        additional: list[DNSRecord],
        budget: Budget,
    ) -> list[str] | None:
        """Return referral server IPs, resolving names without usable glue."""
        # Prefer matching A glue from the referral response.
        candidates = [
            address.data
            for nameserver in referred
            for address in additional
            if address.rrtype == TYPE_A
            and address.rrclass == CLASS_IN
            and norm(address.owner) == norm(nameserver.data)
        ]
        if candidates:
            return candidates

        # Resolve nameserver addresses recursively when glue is unavailable.
        for nameserver in referred:
            if budget.referrals >= 10:
                return None
            budget.referrals += 1
            nested = self.resolve(
                parser.Question(nameserver.data, TYPE_A, CLASS_IN), budget
            )
            if nested and nested.rcode == 0:
                candidates.extend(
                    record.data
                    for record in nested.answers
                    if record.rrtype == TYPE_A
                )
            if candidates:
                break
        return candidates

    def resolve(
        self, question: parser.Question, budget: Budget
    ) -> Resolution | None:
        """Iteratively resolve one question and retain CNAME links."""
        # Start each lookup at the root and retain aliases across restarts.
        root_candidates = self._root_candidates()
        candidates = list(root_candidates)
        current = question.name
        current_zone = "."
        chain: list[DNSRecord] = []
        levels = 0

        # Descend through at most ten referrals within the shared budget.
        while (
            candidates
            and levels <= 10
            and time.monotonic() < budget.deadline
        ):
            progressed = False
            for candidate in candidates:
                # Try each server at this level until one advances resolution.
                response = self.upstream_query(
                    candidate,
                    parser.Question(current, question.qtype, question.qclass),
                    budget,
                )
                if response is None:
                    continue
                flags, answers, authority, additional = response
                aa, rcode = bool(flags & 0x0400), flags & 15

                # Retain same-packet aliases before authoritative NXDOMAIN.
                if rcode == 3 and aa:
                    chain_before_response = len(chain)
                    if not self._retain_negative_aliases(
                        current,
                        chain,
                        answers,
                        question.qclass,
                        budget,
                    ):
                        return None
                    return Resolution(
                        3, chain, chain_before_response == 0
                    )
                if rcode != 0:
                    continue

                # Use direct answers or follow aliases contained in this packet.
                result, cname_target, failed = self._follow_answer_chain(
                    question, current, chain, answers, aa, budget
                )
                if result is not None:
                    return result
                if failed:
                    return None
                if cname_target is not None:
                    candidates = list(root_candidates)
                    current = cname_target
                    current_zone = "."
                    levels = 0
                    progressed = True
                    break

                # An authoritative empty response is a final NODATA result.
                if aa:  # authoritative NOERROR/NODATA
                    return Resolution(0, chain, not chain)

                # Validate and collect a referral for the current DNS branch.
                referral_zone, referred = self._referred_nameservers(
                    authority, current, current_zone
                )
                if not referred:
                    continue
                if budget.referrals >= 10:
                    return None
                budget.referrals += 1

                # Find the next-hop server through glue or a nested A lookup.
                next_candidates = self._referral_candidates(
                    referred, additional, budget
                )
                if next_candidates is None:
                    return None
                candidates = next_candidates
                if not candidates:
                    # This referring server did not yield a usable next hop;
                    # continue trying the remaining current-level candidates.
                    continue
                current_zone = referral_zone
                levels += 1
                progressed = True
                break

            # Fail when no server at the current level can make progress.
            if not progressed:
                return None
        return None

    def response(self, query_data: bytes) -> bytes | None:
        """Resolve one client packet and construct its DNS response."""
        # Parse exactly one client question from the datagram.
        message_id, flags, questions, _, _, _ = parser.parse_message(query_data)
        if len(questions) != 1:
            return None

        # Initialise the response sections and status.
        question = questions[0]
        answers: list[DNSRecord] = []
        additional: list[DNSRecord] = []
        rcode = 0
        direct_authoritative = False

        # Answer root-hints-local questions without contacting upstream servers.
        local = self.root_local(question)
        if local is not None:
            if question.qtype == TYPE_NS and norm(question.name) == ".":
                for record in local:
                    if record.rrtype == TYPE_NS:
                        answers.append(record)
                    if record.rrtype == TYPE_A:
                        additional.append(record)
            else:
                answers = local

        # Reject question types and classes outside the supported assignment set.
        elif (
            question.qtype not in SUPPORTED_TYPES
            or question.qclass != CLASS_IN
        ):
            rcode = 2

        # Use a complete cache hit or perform a budgeted iterative resolution.
        else:
            answers = self.cached(question) or []
            if not answers:
                budget = Budget(time.monotonic() + min(30, 50 * self.timeout))
                result = self.resolve(question, budget)
                if result is None:
                    rcode = 2
                else:
                    rcode, answers = result.rcode, result.answers
                    direct_authoritative = result.direct_authoritative

                    # Cache only positive answers that fit a successful packet.
                    if rcode == 0 and answers:
                        preview = self.build_client_response(
                            message_id,
                            flags,
                            question,
                            rcode,
                            answers,
                            additional,
                            direct_authoritative,
                        )
                        if parser.parse_message(preview)[1] & 15 == 0:
                            self.cache_records(answers)

        # Encode the final response with the original transaction metadata.
        return self.build_client_response(
            message_id,
            flags,
            question,
            rcode,
            answers,
            additional,
            direct_authoritative,
        )

    def build_client_response(
        self,
        message_id: int,
        query_flags: int,
        question: parser.Question,
        rcode: int,
        answers: list[DNSRecord],
        additional: list[DNSRecord],
        direct_authoritative: bool = False,
    ) -> bytes:
        """Encode a standards-compliant response to one client question."""
        # Preserve client opcode and RD while marking the response recursive.
        encoder = Encoder()
        response_flags = (
            0x8000
            | (query_flags & 0x7800)
            | (query_flags & 0x0100)
            | 0x0080
            | (0x0400 if direct_authoritative else 0)
            | rcode
        )

        # Write the response header and original question.
        encoder.data.extend(
            struct.pack(
                "!HHHHHH",
                message_id,
                response_flags,
                1,
                len(answers),
                0,
                len(additional),
            )
        )
        encoder.question(question)

        # Append answer and additional records in their selected order.
        for record in answers:
            encoder.record(record)
        for record in additional:
            encoder.record(record)

        # Keep valid UDP-sized packets and replace oversized data with SERVFAIL.
        if len(encoder.data) <= MAX_UDP_DNS_MESSAGE:
            return bytes(encoder.data)
        return self.build_client_response(
            message_id, query_flags, question, 2, [], []
        )


def serve(
    root_hints_file: str,
    timeout: int,
    listen_port: int,
    stop_event: threading.Event | None = None,
    ready: threading.Event | None = None,
) -> None:
    """Bind the loopback UDP server and handle independent client requests."""
    # Initialise shared resolver state before accepting clients.
    resolver = Resolver(root_hints_file, timeout)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", listen_port))
        sock.settimeout(0.1)
        if ready is not None:
            ready.set()

        # Receive requests until the optional test stop event is raised.
        while stop_event is None or not stop_event.is_set():
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue

            # Resolve each datagram independently so slow clients do not block.
            def handle(
                query: bytes = data,
                client: tuple[str, int] = address,
            ) -> None:
                """Resolve one datagram in a dedicated worker thread."""
                try:
                    response = resolver.response(query)
                    if response is not None:
                        sock.sendto(response, client)
                except (
                    parser.DNSParseError,
                    ValueError,
                    struct.error,
                    OSError,
                ):
                    return

            # Detach the short-lived worker from server shutdown.
            threading.Thread(target=handle, daemon=True).start()


# Compatibility helpers for the supplied programmatic test suite.  The assessed
# interface remains the Resolver class and resolver.py command line.
def cache_store(
    records,
    cache: dict,
    lock: threading.Lock,
    now: float | None = None,
) -> None:
    """Replace compatibility-API RRsets with fresh absolute expiries."""
    now = time.monotonic() if now is None else now
    grouped = {}

    # Group positive-TTL records into complete compatibility RRsets.
    for record in records:
        if record.ttl > 0:
            key = (norm(record.owner), record.rtype, record.rclass)
            grouped.setdefault(key, []).append((record, now + record.ttl))

    # Replace each grouped RRset while holding the caller's cache lock.
    with lock:
        for key, entries in grouped.items():
            cache[key] = entries


def cache_lookup(
    question,
    cache: dict,
    lock: threading.Lock,
    now: float | None = None,
):
    """Return a complete compatibility-API cached response, if available."""
    now = time.monotonic() if now is None else now

    def get(name, rtype):
        """Return one unexpired cached RRset with floor-adjusted TTLs."""
        # Remove expired entries under the caller's cache lock.
        key = (norm(name), rtype, question.qclass)
        with lock:
            entries = []
            remaining_ttls = []
            for record, expiry in cache.get(key, []):
                remaining = int(expiry - now)
                if remaining > 0:
                    entries.append((record, expiry))
                    remaining_ttls.append(remaining)
            if entries:
                cache[key] = entries
            else:
                cache.pop(key, None)

        # Recreate live records with their remaining whole-second TTLs.
        records = []
        for (record, _), remaining in zip(entries, remaining_ttls):
            records.append(
                type(record)(
                    record.owner,
                    record.rtype,
                    record.rclass,
                    remaining,
                    record.data,
                )
            )
        return records

    # Return direct CNAME queries without following the alias target.
    if question.qtype == TYPE_CNAME:
        aliases = get(question.name, TYPE_CNAME)
        if not aliases or len(aliases) > 10:
            return None
        target = norm(aliases[0].data)
        if any(norm(alias.data) != target for alias in aliases):
            return None
        return tuple(aliases)

    # Follow complete, consistent cached CNAME RRsets to a final answer.
    chain = []
    current = question.name
    seen = {norm(current)}
    for cname_count in range(11):
        final = get(current, question.qtype)
        if final:
            return tuple(chain + final)
        if cname_count == 10:
            return None
        aliases = get(current, TYPE_CNAME)
        if not aliases:
            return None

        # Reject conflicting targets, loops, and chains beyond ten aliases.
        target = norm(aliases[0].data)
        for alias in aliases:
            if norm(alias.data) != target:
                return None
        if len(chain) + len(aliases) > 10:
            return None
        if target in seen:
            return None
        chain.extend(aliases)
        current = aliases[0].data
        seen.add(target)
    return None


def process_client_query(
    packet: bytes,
    hints: list[DNSRecord],
    timeout: float,
    cache: dict,
    cache_lock: threading.Lock,
) -> bytes:
    """Process a packet through a temporary resolver for compatibility tests."""
    # Attach caller-owned hints, timing, and cache state without reading a file.
    instance = Resolver.__new__(Resolver)
    instance.hints = hints
    instance.timeout = timeout
    instance.cache = cache
    instance.cache_lock = cache_lock
    return instance.response(packet)


def resolve_question(question, hints: list[DNSRecord], timeout: float = 2):
    """Programmatic convenience wrapper used by optional smoke tests."""
    # Import lazily to avoid coupling the assessed command-line path.
    from dns_message import build_query, parse_message

    # Resolve one generated query through an isolated in-memory resolver.
    instance = Resolver.__new__(Resolver)
    instance.hints = hints
    instance.timeout = timeout
    instance.cache = {}
    instance.cache_lock = threading.Lock()
    return parse_message(instance.response(build_query(0, question)))


def main(argv: list[str]) -> int:
    """Run the resolver command-line interface and return its exit status."""
    # Validate the three required command-line arguments.
    if len(argv) != 4:
        print(
            f"Usage: {Path(argv[0]).name} root_hints_file timeout listen_port",
            file=sys.stderr,
        )
        return 2

    # Parse settings and run until interrupted or an expected startup failure.
    try:
        timeout, port = int(argv[2]), int(argv[3])
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        serve(argv[1], timeout, port)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as error:
        print(f"Resolver error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
