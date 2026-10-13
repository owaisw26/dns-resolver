# Test suite

Run the complete test suite from the project root:

```sh
python3 -m unittest discover -s tests -v
```

The tests are divided by stage. Black-box tests use the CLI and UDP interfaces;
unit and integration tests also exercise the message helpers and resolver core:

- `ParserBlackBoxTests`: supplied packets, multiple questions, unknown types, and
  malformed compression via `python3 parser.py <message_file>`.
- `ResolverBlackBoxTests`: root-hints-local answers, response flags, unsupported
  types, and concurrent UDP clients via `python3 resolver.py ...`.
- `ResolverIntegrationTests`: scripted referrals, CNAMEs, cache behaviour,
  failover, limits, and malformed upstream responses.
- `ResolverComplianceRegressions`: mixed-case compression, authoritative
  CNAME/NXDOMAIN chains, exact CNAME limits, immediate candidate failover,
  IN-class glue validation, socket failures, and client response metadata.
- `ResolverConcurrencyTests`: slow-versus-fast isolation, response-ID matching,
  and a deterministic 200-request cold/warm cache stress test.
- `LiveResolverBlackBoxTests`: optional public-DNS iterative smoke test, enabled
  only with `RUN_LIVE_DNS=1`.

They use only Python's standard library. Released sample packets and root hints
in `dns-assignment-resources/` are tested by default. The two optional live tests
are separated because public DNS and network availability are nondeterministic.
