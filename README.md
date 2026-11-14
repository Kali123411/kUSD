# kUSD — a covenant-native USD stablecoin on Kaspa L1

[![kUSD v2 tests](https://github.com/Kali123411/kUSD/actions/workflows/v2-tests.yml/badge.svg)](https://github.com/Kali123411/kUSD/actions/workflows/v2-tests.yml)

**TN10 testnet research software. Not audited. Not a product. Not for real value.**

kUSD is a complete CDP stablecoin living entirely in Kaspa covenants: USD cents in
covenant state (`value ≠ amount`), a ≥175% collateralized vault system, a USD-priced
redemption reserve (the peg floor — permissionless; governance can't block it), an
oracle fed by five independent operators (each refresh takes the median of three
separately signed prints), safety rails (rate-limited mint and liquidation prices,
stale-feed shutdown, a daily net issuance budget), an on-chain treasury with a
governance fee switch (demonstrated live, shipped OFF), and atomic liquidations with a
keeper/treasury split. No bridge, no L2, no trusted issuer.

Start here:

- **[Whitepaper](docs/pitch/WHITEPAPER.md)** — thesis, architecture, security model,
  live evidence, economics, roadmap.
- **[One-pager](docs/pitch/ONE-PAGER.md)** — the short version + how to support the work.
- **[Protocol README](contracts/v2/README.md)** — design and the metering table.
- **[Deploy runbook + live state](contracts/v2/deploy/README.md)** — every covenant id
  and transaction id from the TN10 deployments.
- **[Evidence archive](docs/pitch/evidence/)** — every cited transaction, serialized,
  re-verifiable offline against the node's own covenant engine (TN10 resets cannot
  erase it).

## Verify the claims

```bash
# needs only Rust (stable) and protoc; argent is pinned as a git dependency
cd contracts/v2/harness
cargo test --release --locked   # 182 tests: protocol, KCC-20 conformance vectors,
                                # and every security-review attack as a regression
cargo test --release -- --nocapture | grep compute_mass   # regenerate the metering table
```

The contracts are in `contracts/v2/ag/` (Argent): `kusd.ag` (KCC-20 token + supply
authority + emission gate), `vault.ag` (CDP), `psm.ag` (redemption reserve + fee
switch), `oracle.ag` (five-operator signed-print feed with rate-limited prices and
freeze/settle), `budget.ag` (daily net issuance budget), `surplus.ag` (treasury). The vendored KCC-20
reference and conformance fixture are under `contracts/v2/vendor/kcc20/` (ISC,
provenance documented).

## History

Built in phases during 2026: the KCC-20 port proving `value ≠ amount`, the redemption PSM and
emission-gate hardening, the first live TN10 deployment, and the Phase 4
completion — KCC-20 interface conformance, fee switch, penalty split, vault close,
four adversarial security reviews with attack-transaction regression tests, and a
full re-deployment under real consensus. Phase 5 added the safety rails, proven live
through a frozen feed and a 75% price crash absorbed by the rate limit before an atomic
liquidation. Oracle Stage 1 replaced the 2-of-3 committee with five independent
operators signing prices offline, live with relayed refreshes and a key rotation.
Every entry has run on TN10 except the 30-day settlement, which is covered by tests.
CI runs the full suite on every change.

## License

MIT — see [LICENSE](LICENSE). The vendored KCC-20 reference under
`contracts/v2/vendor/kcc20/` remains under its own ISC license.

## Safety

This repository exists so claims can be verified, not so the system can be used.
Nothing here is audited; TN10 covenants and keys are worthless by design; do not
deploy this with real value.
