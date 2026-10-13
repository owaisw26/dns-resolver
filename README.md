# DNS Resolver

A Python implementation of a DNS wire-message parser and an iterative UDP resolver. Built for UNSW COMP3331/9331, this project starts with root hints, follows DNS referrals, handles aliases, and caches positive answers. It uses only the Python standard library.

## What it does

- **Inspect DNS packets:** decode headers, questions, and resource records, including compressed names and A, NS, CNAME, PTR, and MX data.
- **Resolve names iteratively:** query root servers, follow relevant NS referrals, use glue records or look up a name server's address, and follow CNAME chains.
- **Serve concurrent clients:** respond over UDP on localhost with per-request resolution state and a shared, lock-protected TTL cache.
- **Handle failures:** reject malformed packets, check upstream response identity, try alternative servers, and enforce time and traversal limits.

## Quick start

Requires Python 3.10 or newer. No packages need to be installed.

Print a supplied DNS response packet:

```sh
python3 parser.py dns-assignment-resources/www.example.com-A-CNAME-12001-response.bin
```

Start the resolver on localhost (port `5300`, with a 2-second upstream timeout):

```sh
python3 resolver.py dns-assignment-resources/named.root 2 5300
```

In another terminal, try a root-hints-local query with `dig`:

```sh
dig @127.0.0.1 -p 5300 . NS +norecurse
```

For a public-domain lookup, replace `. NS` with a name and supported record type, such as `example.com A`. These lookups need network access to authoritative DNS servers. Stop the resolver with `Ctrl+C`.

## Tests

Run the standard-library test suite from the project root:

```sh
python3 -m unittest discover -s tests -v
```

The suite covers parser boundaries, command-line behavior, root-hints responses, referrals, caching, CNAME and negative answers, failover, malformed upstream replies, and concurrent UDP clients. Its local scripted DNS servers make the core tests independent of public DNS. Two optional live-network smoke tests run only when `RUN_LIVE_DNS=1`; see [tests/README.md](tests/README.md).

## Project layout

| Path | Purpose |
| --- | --- |
| [`parser.py`](parser.py) | DNS packet decoder and command-line inspector |
| [`resolver.py`](resolver.py) | UDP server, iterative lookup, response encoder, and cache |
| [`dns_message.py`](dns_message.py) | Programmatic DNS message helpers used by tests |
| [`dns-assignment-resources/`](dns-assignment-resources/) | Released packet samples, checksums, and root hints |
| [`tests/`](tests/) | Unit, black-box, integration, and regression tests |
| [`docs/report.pdf`](docs/report.pdf) | Technical report with design and performance results |

## Scope

The resolver supports IPv4 UDP and IN-class A, NS, CNAME, PTR, and MX questions. It is an educational implementation: it does not provide TCP fallback, IPv6, EDNS, DNSSEC validation, persistent or negative caching, or unbounded production traffic handling. Responses follow the assignment's classic 512-byte UDP limit. The [technical report](docs/report.pdf) explains the algorithms, tradeoffs, tests, and measured results in more detail; its [LaTeX source](docs/report.tex) and [AI-use log](docs/ai-log.txt) are included.
