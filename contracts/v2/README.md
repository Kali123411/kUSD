# kUSD v2 — USD-denominated stablecoin core on Argent / SilverScript 1.0 (KCC-20-shaped)

[![kUSD v2 tests](https://github.com/Kali123411/kUSD/actions/workflows/v2-tests.yml/badge.svg)](https://github.com/Kali123411/kUSD/actions/workflows/v2-tests.yml)

Research port of the kUSD protocol with **USD-denominated amounts in covenant state**
(`value ≠ amount`) — the peg-critical decoupling v1 could not express. Phase 1 = the CDP
core; Phase 2 = the redemption PSM (peg floor), multi-gate emission config, vault adjust,
authority rotation, and the deploy path. Phase 3 (2026-11-11) = **live TN10 deployment**:
full genesis sequence, a live USD-denominated mint, and a swap_in/swap_out redemption
cycle, all confirmed in the consensus UTXO set with every genesis covid cross-verified by
`argentc genesis verify` (`deploy/README.md` "Live state"). Not audited, not a product;
TN10-and-below research only. The phase-by-phase history is in the root README and
`deploy/README.md` ("Live state").

## Headline results (2026-11-11)

- **The `value ≠ amount` blocker is gone.** SilverScript 1.0's
  `validateOutputStateWithInputTemplate` (the mechanism our
  an earlier upstream RFC asked for) sources the counterpart
  template from a co-spent input's revealed script — O(1) in the calling script. Argent's
  `observes { inputs/outputs } ... become` lowers to it automatically.
- **The ATOMIC liquidate fits.** v1's 5-covenant liquidate sat ~0.3% under the 500k
  compute-mass cap and needed a decoupled two-phase fallback. The v2 atomic 4-covenant
  liquidate meters at **22,488 compute mass (4.5% of the cap)**. The two-phase design is
  unnecessary on this stack.
- kUSD amounts are USD cents in KCC-20-shaped state; a mint of $2.00 against 10 KAS at a
  committee-oracle price executes under the node-equivalent covenant engine.
- **The peg floor exists in-covenant (Phase 2):** a USD-priced redemption PSM —
  `swap_out` burns kUSD for $1-worth of KAS from the reserve at the oracle price,
  permissionless and NEVER ceiling-blocked — with no bridged stable anywhere in the stack.
- **The stack is live on TN10 (Phase 3, 2026-11-11):** oracle → unwired PSM → authority →
  wire → vault genesis'd under real consensus (kaspad v2.1.0), every covid reproduced
  independently by `argentc genesis verify --require-argent`, then a live $2.00 mint
  against 10 TKAS and a full 400-cent swap_in/swap_out redemption loop, all confirmed in
  the consensus UTXO set (`deploy/README.md` "Live state"). Heaviest live tx: 24,437
  compute mass (~4.9% of the cap).

## Metering table (mainnet limits: compute 500,000 / transient 1,000,000; storage is contextual)

| path | covenant inputs | per-input script units | compute mass | % cap | transient mass | % cap |
|---|---|---|---|---|---|---|
| **mint** (vault+authority+oracle+budget meter) | 4 | 472,999 / 167,468 / 18,022 / 208,221 | **37,790** | 7.6% | 110,160 | 11.0% |
| **repay** (vault+authority+holder+budget credit) | 4 | 406,748 / 138,787 / 114,357 / 187,424 | **40,871** | 8.2% | 126,244 | 12.6% |
| **liquidate, ATOMIC, split** (+oracle+surplus+budget credit) | 6 | 461,735 / 138,787 / 114,357 / 18,022 / 3,857 / 187,428 | **46,092** | 9.2% | 139,928 | 14.0% |
| **swap_in** (psm+authority+oracle+budget meter) | 4 | 397,000 / 194,262 / 18,022 / 208,221 | **41,095** | 8.2% | 125,380 | 12.5% |
| **swap_out** (psm+authority+holder+oracle+budget credit) | 5 | 476,626 / 165,593 / 114,357 / 18,022 / 187,428 | **49,351** | 9.9% | 152,844 | 15.3% |
| **swap_in_fee** (+surplus) | 5 | 406,087 / 194,262 / 3,857 / 18,022 / 208,221 | **42,210** | 8.4% | 127,960 | 12.8% |
| **swap_out_fee** (+surplus) | 6 | 485,721 / 165,598 / 114,357 / 3,857 / 18,022 / 187,428 | **50,466** | 10.1% | 155,424 | 15.5% |
| adjust (vault+authority+oracle) | 3 | 345,212 / 138,206 / 18,022 | 29,665 | 5.9% | 95,020 | 9.5% |
| close (vault+authority, frozen) | 2 | 244,422 / 138,200 | 25,415 | 5.1% | 83,940 | 8.4% |
| set_params (psm+authority) | 2 | 423,870 / 165,043 | 31,470 | 6.3% | — | — |
| psm wire (one-time, 3 ids) | 1 | 306,686 | 21,080 | 4.2% | — | — |
| kusd transfer 2-in/2-out (witness ABI) | 2 | 173,098 / 114,337 | 17,977 | 3.6% | 57,748 | 5.8% |
| kusd borrowed-receive (threshold) | 2 | 72,923 / 114,337 | 16,911 | 3.4% | — | — |
| surplus receive / spend | 1 | 3,847 / 204,495 | 1,159 / 3,689 | 0.7% | 3,836 | 0.4% |
| budget set_limit (gov, settles refill) | 1 | 222,348 | 6,350 | 1.3% | — | — |
| authority rotate | 1 | 142,320 | 8,959 | 1.8% | — | — |
| oracle refresh (median of 3 signed prints, rate-limited) | 1 | 320,504 | 6,665 | 1.3% | — | — |
| oracle set_member (3 signers, never the replaced slot) | 1 | 320,439 | 6,622 | 1.3% | — | — |
| oracle freeze (permissionless) | 1 | 18,017 | 3,345 | 0.7% | — | — |
| oracle peek (passthrough) | 1 | 18,012 | 3,290 | 0.7% | — | — |

(Numbers from the oracle Stage 1 contracts — five operators, median of three signed
prints; the larger oracle state adds ~2–3k compute mass to every path that co-spends
it — on top of Phase 5's rate-limited mint/liq prices (1e-4 USD precision, one hour of rate per refresh), oracle freeze/settle,
and NET budget metering — every issuance draws from and every burn credits the global
token bucket, with the budget authenticating the supply authority itself. Script units
vary a few units run-to-run with signature bytes; masses computed by the node's own
`MassCalculator` after committing minimal `ComputeBudget`s per input. Worst path
(swap_out_fee, 6 covenant inputs) uses 10.1% of the compute cap and 15.5% of the
transient cap. Comparison point: v1's mint was ~211k compute mass and liquidate ~498k.)

## Design (one screen)

- **`ag/kusd.ag`** — the token, now at the FULL KCC-20 interface (Phase 4): the
  reference witness-blob `transfer` ABI (path selector, KCC-2 owner schemes 0x00–0x03
  on outputs — 0x04 rejected as declared deviation D4 — and all four borrow schemes
  including borrowed receive and hash-chain guards), with a self-authorizing
  `transfer_delegator` on every co-spent kUSD input (the check-free `join` delegate was
  REMOVED — argent delegation authenticates the actor, not the entry). Amount is
  conserved; exact value conservation was dropped for KCC-20 semantics (per-output
  `value >= DUST` floor instead). The supply authority is marker `0x10` (out of KCC-2's
  range), frozen under `transfer`. `emission` (authority-only leader) changes supply
  only when a co-spent EMITTER — vault or THE PSM — passes the gate:
  `extension_commitment = blake3(vault_template || psm_template || oracle_covid ||
  psm_covid || surplus_covid || budget_covid)` (192-byte preimage as witness args;
  Phase 5 added the budget), `gate.kusd_id == self.cov_id`, the anchored oracle, the
  PSM pinned by covid (C-1), and the anchored surplus and budget
  (`gate.surplus_id` / `gate.budget_id` == the config's covids). `rotate` migrates
  the authority's governance key.
- **`ag/oracle.ag`** — price feed (1e-4 USD per KAS, `price <= 1e8`) from five operators
  `m0..m4` (oracle roadmap Stage 1). Each signs its own print offline over
  `blake2b(oracle_covid ‖ epoch ‖ price ‖ signed_at_daa)` (`checkMsgSig`); `refresh`
  takes three prints from distinct operators, requires a strictly-increasing epoch, no
  print dated after the clock input, and a spread within 3% (+1 unit), and uses the
  **median** price; the feed's time is the median signed-at, and a FROZEN feed revives
  only with prints signed after the silence. `set_member` rotates a slot with three
  signatures from other slots (refused when settled). Phase 5
  derives two rate-limited prices from the raw print: `mint_price` (borrowing, swap_in)
  follows the market down at once but rises at most 10% per refresh; `liq_price`
  (liquidation, swap_out) rises at once but falls at most 25% per refresh; each refresh
  applies at most one hour (36,000 DAA) of rate, and at least one unit once time has
  elapsed. Time is `OpTxInputDaaScore(clock_idx)`, a consensus lower bound. `freeze` is
  permissionless after >36,000 DAA of silence (mint, withdraw, liquidate and swap_in
  require LIVE); `settle` after 30 days is permanent. `peek` is the free passthrough.
  Vaults pin the feed by **covid** (`oracle_id` state), since templates are forgeable.
- **`ag/psm.ag`** — the redemption reserve. `swap_in` mints kUSD against KAS
  deposited at the oracle price, capped by a 2-of-3-governed `ceiling_cents`; `swap_out`
  redeems kUSD for KAS at `liq_price` — permissionless, never ceiling-blocked,
  bounded by the PSM's own `minted_cents` and paid from the reserve's KAS while it
  lasts (no pro-rata: see the whitepaper's known limits). swap_in meters the issuance
  budget; swap_out credits it. Phase 4 adds the FEE SWITCH: `spread_bps`
  (0–200, governance `set_params`) with `swap_in_fee`/`swap_out_fee` routing the KAS
  spread to the covid-pinned surplus box (plain swaps require spread 0 — no dead-weight
  input when fees are off). Every entry pins its own singleton lineage to tx input 0
  (review C1: single-emitter exclusivity) and co-spends the kusd family frozen where it
  moves no supply.
- **`ag/surplus.ag`** — the governance treasury (Phase 4). Box value IS the balance:
  permissionless `receive` (value never decreases, state frozen), 2-of-3 `spend` with a
  consensus-pinned P2PK destination and a tombstone floor. Pinned by COVID by its
  spenders; funded by the PSM spread and the liquidation split.
- **`ag/budget.ag`** — the net issuance budget (Phase 5). A token bucket: `limit` cents
  refill fully over 864,000 DAA (24h). `meter(d)` draws down on every supply increase
  (vault mint, swap_in), `credit(r)` refunds on every burn (repay, liquidate, swap_out),
  capped at the limit; both authenticate the real authority (owner scheme 0x10) and bind
  d/r to its actual amount change, so transfers and round trips can't drain or grief it.
  `set_limit` (governance) settles the refill first; `wire` is one-time.
- **`ag/vault.ag`** — the CDP. `VaultState { owner, collateral, debt, kusd_id,
  oracle_id, surplus_id, budget_id }`, box invariant `value >= TOMBSTONE + collateral`.
  `mint`/`repay`/`adjust`/`liquidate`/`close` each observe and FULLY pin the kusd
  family (frozen where no supply moves, `close` included) and pin themselves to tx
  input 0 (review C1). Collateral is frozen while debt remains, releasable at debt 0,
  and `close` (emits none) terminates the lineage. Parameters: MIN_RATIO 175%, the 13%
  penalty SPLIT keeper 110%-of-debt / surplus 3% (keeper first when capped, clamped to
  the KIP-9 floor), MIN_COLLATERAL 2 KAS and MIN_DEBT $1 (review I4 — dust vaults were
  unliquidatable), seize capped at freed collateral, owner keeps the remainder
  in the closed vault.
  Bounds: collateral ≤ 4e12 sompi, debt ≤ 4e10 cents, price ≤ 1e8 (1e-4 USD) — every
  product stays inside i64.

**Fragile couplings (cascade on change):** kusd.ag's `VaultGate` mirror struct must match
`VaultState`'s field layout exactly; the vault handle template hash (= every box's
`extension_commitment`) changes whenever vault.ag changes. Same cascade discipline as v1
(repo conventions).

## Toolchain pin

- [argent-lang/argent](https://github.com/argent-lang/argent) at commit **0cf5b30**
  (2026-11-12), pinned as a **git dependency** in `harness/Cargo.toml`: a fresh clone
  runs `cargo test --release` with no other checkout needed.
- silverscript-lang / silverscript-abi **1.0.1** (crates.io, transitive via argent).
- kaspa-* **2.1.0** crates, Rust edition 2024 (rustc ≥ 1.94).

## Layout & run

- `ag/` — Argent sources (kusd.ag, oracle.ag, vault.ag; vault imports the other two and
  cross-app references use `KusdApp::Kusd` syntax).
- `harness/` — Rust test crate; builds the apps (`argent::build_file_app_bundle`) and
  meters every transaction with the covenant txscript engine against mainnet limits
  (`harness/src/lib.rs::meter`).
- `build/` — generated artifacts (git-ignored).

```bash
cd contracts/v2/harness
cargo test -- --nocapture     # meter lines print as `MINT: units=[..] compute_mass=..`
```

116 tests: KCC-20 token ABI incl. scheme matrix, borrow paths and witness
malformation (24), KCC-20 conformance vectors driven by the official fixture (6),
oracle (7), PSM incl. hostile-instance / rider / wire / fee switch (25), mint/repay +
emission-gate adversarial (16), adjust/rotate (7), liquidate incl. the 110/3 split (9),
close (5), surplus (9), security-review attack regressions (5), genesis (2), smoke (1).
Negative tests assert the SPECIFIC rejection reason; the emission gate's threat model is
pinned for BOTH gate kinds (unrelated-family riders on both, hostile oracle wiring,
hostile PSM instance, config forgery, gate-kind confusion, non-vault gate, forged
oracle input).

## Mass caveat

The harness enforces **compute + transient** mass (non-contextual). **Storage mass
(KIP-9) is contextual** and not checked here — covenant box values respect the
100M-sompi (`TOMBSTONE`/`DUST`) convention from v1 to stay under it.

## Out of this slice

External audits (the first funded item), oracle operator decentralization, stability
fees (DAA-based accrual — designed, not built), keeper bots, KCC-23 metadata, mainnet.
The economic gates are unchanged: independent oracle operators (or the miner oracle), peg economics beyond the PSM
reserve, liquidity.
