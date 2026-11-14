# kUSD v2 — TN10 deploy runbook (LIVE on TN10 since 2026-11-11)

Status: the full v2 stack is **deployed and exercised live on TN10** (2026-11-11): the whole
genesis sequence below was executed in order, every genesis covid was cross-checked with
`argentc genesis verify --require-argent` against the node's covid, and a live
USD-denominated mint plus a full PSM swap_in/swap_out redemption cycle are confirmed in the
consensus UTXO set (see "Live state"). The driver is
`harness/src/bin/tn10_deploy.rs` (stage-driven, local pre-verify + DRY_RUN gate before
every broadcast). TN10 resets periodically; the Live state section is dated and the whole
sequence re-runs after a reset.

## Prerequisites

- A synced TN10 `kaspad` (rusty-kaspa ≥ 2.1.0) with RPC reachable; TKAS from the faucet.
- `argentc` built from the pinned checkout (the argent-lang/argent commit pinned in
  `contracts/v2/harness/Cargo.toml`).
- Env (never committed): `KUSD_DEPLOY_KEY` (funding/change key), the 3 oracle committee
  keys, the 3 PSM governance keys, the authority governance key.

## Genesis order (circularity-free)

The gate config freezes `extension_commitment = blake3(vault_template || psm_template ||
oracle_covid || psm_covid || surplus_covid || budget_covid)` (192-byte preimage) into the
authority's state at its genesis, so everything that contributes to the config must exist
(as a TEMPLATE) or be known (the four covids) first. Prices are in **1e-4 USD per KAS**
(Phase 5).

1. **Compile** `ag/vault.ag` (VaultApp) and `ag/psm.ag` (PsmApp) and record the `Vault`
   and `Psm` actor-type-handle template hashes (the harness's `gate_setup` shows exactly
   which fields: `argent.template_plan.templates[].actor_type_handle.template`).
2. **Oracle genesis** — five DISTINCT operator pubkeys `m0..m4` (the driver asserts
   this), `price = mint_price = liq_price` (genesis print), epoch 0, `last_update` = a recent DAA score, `status = 0`. Compose/verify:
   `argentc genesis compose ag/oracle.ag --bootstrap <boot.json> --out oracle_proof.json`
   then `argentc genesis verify oracle_proof.json --covenant-id <covid from the node>
   --require-argent`. **Record ORACLE_COVID.**
3. **PSM genesis, UNWIRED** — `kusd_id`, `surplus_id`, `budget_id` all `0x00…00`,
   `oracle_id = ORACLE_COVID`, governance pubkeys, `ceiling_cents`, `minted_cents = 0`,
   `spread_bps = 0`. **Record PSM_COVID.**
4. **Surplus genesis** — governance pubkeys, `kusd_id = 0x00…00` (informational).
   **Record SURPLUS_COVID.**
5. **Budget genesis, UNWIRED** (budget.ag) — `daily_limit` = `available` (cents per 24h),
   `last_refill` = a recent DAA score, `kusd_id = 0x00…00`, governance pubkeys.
   **Record BUDGET_COVID.**
6. **Config hash** — `ext = blake3(vault_t || psm_t || ORACLE || PSM || SURPLUS || BUDGET)`
   (192 bytes; reuse the harness's `gate_setup`).
7. **Authority genesis** (kusd.ag) — `owner_scheme = 0x10`, full un-issued supply,
   `borrow_scheme = 0`, `borrow_guard = 0x00…00`, `extension_commitment = ext`.
   **Record KUSD_COVID.**
8. **Wire the PSM** — gov 2-of-3 `Psm::wire(KUSD_COVID, SURPLUS_COVID, BUDGET_COVID)`.
9. **Wire the budget** — gov 2-of-3 `Budget::wire(KUSD_COVID)` (until then `meter`
   refuses, so no issuance is possible).
10. **Vault genesis** (per borrower, permissionless) — `kusd_id`, `oracle_id`,
    `surplus_id`, `budget_id` as recorded, `debt = 0`, `value ≥ TOMBSTONE + collateral`,
    `collateral ≥ 2 KAS`.

### Operating the safety rails (Phase 5)

- **Committee refreshes** carry a `clock_idx`: point it at the freshest input in the tx
  (the committee's own just-confirmed funding UTXO). The mint price can rise ≤10%/h and
  the liquidation price fall ≤25%/h from the last refresh.
- **Refresh at least hourly**, or anyone may `freeze` the feed (mint, withdrawal,
  liquidation and swap_in stop; repay, close, deposits and swap_out continue). A refresh
  un-freezes. 30 days of silence → anyone may `settle` (permanent).
- **Net metering:** every issuance (mint, swap_in[_fee]) co-spends the budget under
  `meter(d, clock_idx, recipient)`; every burn (repay, liquidate, swap_out[_fee]) co-spends
  it under `credit(r, clock_idx)`. The budget authenticates the supply authority and binds
  d / r to its amount change. Governance moves the daily limit with
  `set_limit(..., clock_idx)` (the refill to date settles at the old limit first).
- **Clocks read CONFIRMATION time.** Every clock is a co-spent input's confirmation DAA
  score: refresh right after a fresh confirmation (the driver's `STAGE=touch`), or the
  feed stays stale in consensus' eyes and is freezable at once.
- **Peg floor during crashes:** swap_out pays at the lagging liquidation price —
  deliberately less than $1 of KAS per kUSD until the price catches up.
- **Known gap — settlement:** `settle` is an emergency halt (redemption, repay, close stay
  open); pro-rata settlement of CDP-issued kUSD after a permanent oracle failure is
  designed-not-built.

### Fee-switch demo cycle (Phase 4)

With everything wired: `set_params(ceiling, 25)` (gov 2-of-3) → `swap_in_fee` (spread
lands in the surplus box, covid-pinned) → `swap_out_fee` (spread out of the payout) →
`set_params(ceiling, 0)` (switch back off) → optional `Surplus::spend` (gov 2-of-3,
P2PK dest pinned at outputs[1]). Liquidations always split: keeper 110% of debt,
surplus 3% (keeper first when freed collateral caps the seizure).

## Operating notes

- Every covenant tx should be locally pre-verified before broadcast exactly as the harness
  does (`execute_transaction_with_covenants`); that is the same engine the node runs.
- Storage mass (KIP-9) is NOT checked by the harness: keep every covenant output ≥ 100M
  sompi (TOMBSTONE/DUST convention) and remember a fixed-output covenant can't take change —
  fee comes from input surplus (deploy invariant learned in v1; ~21M sompi fee floor at ~211k
  compute in v1 — v2 compute is ~10x lower, re-derive at deploy time).
- Any edit to vault.ag or psm.ag changes its template hash → new config hash → NEW authority
  (and the old family's ext no longer matches). The cascade is total: re-genesis everything
  below step 1 after a contract change.
- TN10 resets: keep this file's live covids in a dated section and expect to re-run the
  whole sequence after a reset.

## Live state

### 2026-11-11 — full deployment + money cycle (kaspad v2.1.0)

Deploy address `kaspatest:qzqzw7kcxv4rvvckprfsshj6a5xwkq9jgjddhmalftgpmxyq8j6ncheazyg0m`,
funded with 10,000 TKAS (owner KasWare send, utxo `773e6670…cba5:0`). Keys: fresh TN10-only,
`~/.kusd-v2-tn10/` (deploy, oracle0-2 committee, gov0-2 governance). Every tx below was
locally pre-verified (engine + masses) and DRY_RUN-gated before broadcast; "verified ✓"
means `argentc genesis verify <proof> --covenant-id <covid> --require-argent` reproduced the
node-side covid exactly.

| Step | covid | txid | Notes |
|---|---|---|---|
| Oracle genesis | `434720ab94e45f538da526ae4c3940f4341e244ccdad55ed2ccc2d05ad907388` | `0cc1af27b67f21a2857acd45a896feb806ba55ff0c6f2188fc7d0a7a8e37939d` | price 40 c/KAS, epoch 1, 2-of-3 committee; verified ✓ |
| PSM genesis (unwired) | `95a1b3d9c2025cdc52c31aa798b62a5eefa2fbc7fa7754e3b419060deed600cf` | `f13c98583f88311ea11cedae37a248150bf4878ec13d1b7b2affc144c481103b` | `kusd_id = 0x00…00`, ceiling 100,000 cents; verified ✓ |
| Authority genesis | `4d01484fa6126091b1f8ae4c7aad027950470e4385af0d5a7d58f2af71dbe008` | `aa84f61dbafa76c2ba11d1f456a853d9d5f484205eed9b3fd46b1f41fe0f6b10` | supply 100,000,000 cents, `ext = 478d2318…5707` (blake3 gate config over vault/psm templates + oracle/psm covids); verified ✓ |
| Wire PSM | (continues `95a1b3d9…`) | `5851cb4f453c6bcfb5a872f9ff42cb4cc2b5147d8385765f5b815db2c7ae2a5d` | gov 2-of-3 one-time wire to `KUSD_COVID`; PSM box continued under its own covid (covid-identity model live) |
| Vault genesis | `b9eaf74b25e0370aa96855a870193702d27c7453df4840d2e8c4905488b76a3b` | `4c9f0e07447ed70e31ca6ae0da3efd7d4563af6629d00fe271c6083860a05112` | collateral 10 TKAS, debt 0 |
| **MINT** | minted box joins `4d01484f…` | `5aaf558340cd1e56dfa71467457307c53dcf9ef163d72242720cdff1ed2d6c6e` | **200 USD cents minted against 10 TKAS at 40 c/KAS** — value≠amount live (100M-sompi box carrying a 200-cent face) |
| SWAP_IN | holder box joins `4d01484f…` | `62c0e6c1b4fe43f85e5af70e52af58b08f7b47392a7fe6d0d8ebd7325a4d092b` | 10 TKAS → 400 cents at oracle price; reserve +1e9 sompi |
| SWAP_OUT | — | `41861dcd42738718aacb61031eec36dadc6b482935f56435385f8d8d7e5c66ac` | 400 cents burned, 1e9 sompi forced P2PK payout — full redemption loop closed |

On-chain confirmation: the swap_out payout + change appear in the node's utxoindex
(consensus UTXO set, not mempool), which transitively confirms every ancestor tx above.
Live boxes after the cycle: oracle (`…1ed2d6c6e:3` → `…7e5c66ac:3`), psm (`…7e5c66ac:0`,
wired, minted_cents back to 0), authority (`…7e5c66ac:1`, amount 99,999,800), vault
(`…1ed2d6c6e:0`, collateral 1e9, debt 200), minted kUSD (`…1ed2d6c6e:2`, 200 cents,
deploy-owned). Compute cost stayed tiny: heaviest tx (swap_out) 24,437 compute mass of the
500k cap (~4.9%).

Fix found by the first live dry-run (never reached the network): the genesis subgroup path
is `launch::<name>`, not `launch` (`InvalidGenesisPath`); all four genesis stages corrected.
`STAGE=oracleboot|psmboot|kusdboot` emit the real-key bootstrap JSONs for the verify
cross-checks (byte-typed fields need `{"kind":"byte"}`, not `int`, in the Sil ABI).

### 2026-11-11 (later) — full protocol surface exercised live

Every remaining entry was executed on-chain (same discipline: dry-run → pre-verify →
submit; stages added to `tn10_deploy`: transfer/refresh/adjust/setceiling/repay/liquidate/
rotate, env-parameterized box names for multi-vault use):

| Exercise | txid | What it proved |
|---|---|---|
| `transfer` 200c deploy→user2 | `02c1a2add2e90b574be7cc06b1a1e91080d4074b23c449ef1b8b81660113e21a` | KCC-20 custody move, amount+value conservation, leader-sig custody |
| `refresh` 40→45c, epoch 1→2 (committee 0+1) | `a12cc09f39d4d573db312cb12f34b3a62c18bdfd5957485d65e60aa3b914eb57` | 2-of-3 index-selected committee update |
| `adjust` +1 TKAS collateral | `2c4f4637190636126ac74b76b655cac686420975fdd679d9f7a48cd526b25a8d` | collateral move under frozen debt + frozen supply + health check |
| `set_ceiling` 100,000→50,000c (gov 0+2) | `9933d293bb7178688a9fa13c441a3e2dcf32bbfd11f47cbae3c8aa9304141e44` | PSM governance under the frozen family |
| vault2 genesis | `7fd013b858ae430e18cbf62905fb32aa7c332ef0417143f4cb8a3279daee0ff2` | fresh covid `88e3de59…` — per-box genesis identity |
| mint2: 200c at 45c/KAS | `a2e3ba4bd03e588ef61ae7dd70d020297a069412128682dbe205b674b36fbcb5` | second mint at a MOVED oracle price |
| **full `repay` + release** | `05eb9e4147d152e968808b81c062a40dc9f10bf864fe92f90610c06c26477bf0` | 200c burned, debt→0, **1.195e9 sompi collateral released** to owner |
| `refresh` crash 45→20c, epoch 2→3 (committee 1+2) | `44d3f406ebc0d20382acce1d763c22ea350aea973fdbc89bf2a31f35515e424d` | second committee pair; vault1 pushed under MIN_RATIO |
| **`liquidate`** | `9d6590aaa210cc7c2a6d5809791108d88aa573301f5a01fe1ea217fe34bd332c` | keeper (user2) burned the 200c it got by transfer, seized 1e9 sompi (13% penalty, capped at freed collateral) at the forced `tx.outputs[2]` P2PK payout |
| `rotate` gov0→gov1 | `b3cab973b0c7e64cfb0870c6bcdf772dfe1383e12a5117882a90a740582016c1` | authority owner-key rotation (standalone, can't ride) |
| `rotate` gov1→gov0 | `ede9afd5b615f8202ad033d36af06bc2e95991356b1ae236896fa67d539d07be` | rotation back — state restored canonical |

Live compute masses: transfer 9,733 · refresh 4,779 · adjust 20,801 · set_ceiling 18,800 ·
repay 25,333 · liquidate 26,449 · rotate 9,655 (all ≤5.3% of the 500k cap, matching the
offline metering table).

**End-state supply audit (on-chain):** authority amount is back to exactly
**100,000,000 cents = the full genesis supply**. Every cent issued across the whole run
(200 mint + 400 swap_in + 200 mint2 = 800) was burned back (repay 200, swap_out 400,
liquidate 200): zero circulating kUSD, perfect conservation across 14 live transactions.
Final boxes: oracle (price 20, epoch 3), PSM (ceiling 50,000, minted 0, wired), authority
(100M cents, owner gov0), vault1 (closed: collateral 1e8, debt 0), vault2 (released:
collateral 0, debt 0). user2 holds the 1e9-sompi liquidation seizure at its P2PK address.

### 2026-11-11 (Phase 4) — security-hardened family re-deployed; full surface incl. fee demo, borrowed receive, close, split liquidation, surplus governance

The Phase 4 contracts (KCC-20 witness ABI + fee switch + penalty split + close + the
security-review fix pass: single-emitter exclusivity pins, 160-byte gate config with the
surplus covid, dust-vault floors) are a NEW template family — full re-genesis in the
extended order. Every genesis covid reproduced by `argentc genesis verify
--require-argent`; every accepted tx archived under `docs/pitch/evidence/` (serialized
RPC JSON + INDEX.md), so the record survives TN10 resets.

| Step | covid / result | txid |
|---|---|---|
| Oracle genesis (40 c/KAS, epoch 1) | `347c14f8…acac23e` verified ✓ | `d8f1991d…` |
| PSM genesis (unwired, spread 0) | `93ee96b6…6452fcb` verified ✓ | `92e63334…` |
| Surplus genesis (BEFORE authority, review C2) | `00b9bcbf…613f5385` verified ✓ | `561c15b6…` |
| Authority genesis (ext = 160-byte config `c8b0ae08…`) | `a2af8c3b…bc7f0197` verified ✓ | `b6335f74…` |
| Wire (kusd + surplus ids, one-time) | continues `93ee96b6…` | `deca79ef…` |
| Vault genesis | `445c6701…47a597b0` | `a90a2a75…` |
| Mint 200c @40 | value≠amount | `f30b0a25…` |
| Transfer 200c → user2 (witness ABI) | KCC-20 custody | `4c371d2a…` |
| swap_in 400c (0 bps) | reserve +1e9 | `2099bb92…` |
| set_params spread 25 bps (gov 2-of-3) | **fee switch ON** | `91cc22ca…` |
| **swap_in_fee** | **surplus +2,500,000 sompi — live protocol revenue** | `727025a8…` |
| **swap_out_fee** | redeemer nets 997.5M, **surplus +2.5M** | `466cae76…` |
| set_params spread 0 | **fee switch OFF again** | `6421cf41…` (+`ad318c32…`,`0f19cee2…` during ops) |
| swap_in #2 (0 bps) | payer box for the borrow demo | `fdf4a896…` |
| borrow_setup (400c → user3, threshold-0 policy) | KCC-20 §5 | `10ddb0f9…` |
| **borrow_pay: 50c INTO user3's box, NO owner sig** | borrowed receive live | `32869de3…` |
| swap_out 350c (0 bps) | redemption | `0c939997…` |
| refresh 40→45 (committee 0+1) | | `16eb3039…` |
| adjust +1 TKAS | frozen family | `0abffddd…` |
| vault2 genesis / mint2 @45 / FULL repay (1.19e9 released) | lifecycle | `b1e00c70…` / `3b77be28…` / `4135dcc1…` |
| **close vault2** (`emits none`, frozen family) | lineage terminated | `a67542c0…` |
| refresh 45→30 (committee 1+2) | vault1 unhealthy | `73eaa209…` |
| **liquidate: keeper 733,333,333 / SURPLUS +20,000,000** | 110/3 split live | `a3670d1c…` |
| close vault1 (436.7M released) | | `e244ea0e…` |
| **Surplus::spend 20M (gov 2-of-3, pinned P2PK dest)** | revenue withdrawal | `6edb962b…` |
| rotate gov0→gov1→gov0 | | `a650978c…` / `932fe3ea…` |

**End-state audit (consensus UTXO set):** authority amount **99,999,550** = genesis
supply − EXACTLY the 450 cents outstanding (user3's borrow-policy box — the only live
kUSD); PSM `minted_cents` 450 matches; surplus balance **105,000,000 sompi** = genesis
100M + 2.5M + 2.5M swap fees + 20M liquidation split − 20M governance spend — protocol
revenue accounted to the sompi. Deploy balance settled across 9 UTXOs (releases, payouts,
change all present). Fee-floor note learned live: node standardness wants
fee ≥ ~100 sompi × transient mass; the driver now budgets 10M sompi per tx.

### 2026-11-14 (Phase 5) — safety rails live: frozen feed, rate-limited crash, metered issuance

The Phase 5 contracts (two rate-limited prices, stale-feed freeze/settle, the net
issuance budget, plus the security-review fix pass) are a new template family, re-genesis'd
in the 10-step order. All five genesis covids reproduced by `argentc genesis verify
--require-argent`; every accepted tx archived under `docs/pitch/evidence/` (the Phase 4
archive moved to `evidence/phase4/`).

| Step | covid / result | txid |
|---|---|---|
| Oracle genesis (raw/mint/liq 40 c/KAS) | `01d85c38…` verified ✓ | `dee3b070…` |
| PSM genesis (unwired) | `48834a2d…` verified ✓ | `a3e77309…` |
| Surplus genesis | `022110c1…` verified ✓ | `f914d285…` |
| Budget genesis (unwired, limit 5,000,000 c / 24h) | `14998ca8…` verified ✓ | `50be7186…` |
| Authority genesis (192-byte config incl. budget covid) | `6e322983…` verified ✓ | `d8d6072e…` |
| Wire PSM / wire budget (one-time each) | | `d75a5730…` / `3e51dbfd…` |
| Vault genesis | `3bce0f46…` | `eafd0c76…` |
| **freeze** (permissionless, after >36,000 DAA of oracle silence) | status → FROZEN; a mint against it refused by pre-verify | `82f8ffef…` |
| **refresh revives + rate limit**: raw 4000→8000, mint_price 4000→**4400** (+10% cap), liq 8000 | | `9ce3b8cf…` |
| mint 200c (budget-metered) / transfer → user2 / swap_in (metered) | | `6a75462f…` / `405619ed…` / `1e544e4b…` |
| fee switch ON → swap_out_fee + swap_in_fee route to surplus → OFF | | `d6a4079f…` `0975d7a6…` `d71698f3…` `2f99fc0f…` |
| swap_in / swap_out (budget credited) / swap_in | | `014686ff…` / `c573c535…` / `474c3182…` |
| borrow_setup / **borrow_pay** (no owner sig) / swap_out 350c | | `30ecb1d8…` / `1c1b85b7…` / `99f3b036…` |
| adjust | | `fdca457f…` |
| vault2 genesis / mint / repay (budget credited) / close | | `79901a06…` / `425e97f6…` / `0ce75179…` / `b934ec62…` |
| rotate gov0→gov1→gov0 | | `dbeca177…` / `013630e4…` |
| **rate-limited crash**, raw 8000→2000 held for 4 hourly refreshes: liq_price 8000→6000→4500→3375→**2532** (≤25%/h); mint_price 4400→2000 at once | vault1 NOT liquidatable for 3 hours | `049784a3…` `f7b8068f…` `962603e3…` `e0f96529…` |
| **liquidate** at liq_price 2532: keeper 868,870,000 sompi / surplus +23,690,000; budget credited 200c | | `0486065a…` |
| Surplus::spend 20M (gov 2-of-3) | | `ca25e8dd…` |
| close vault1 (297,440,000 released) | | `eadd528d…` |

**End-state audit (consensus UTXO set):** authority amount **99,999,550** = genesis
supply − EXACTLY the 450 cents outstanding (user3's borrow-policy box, the only live kUSD);
PSM `minted` 450 matches; budget `available` back at its 5,000,000 limit (net metering:
every burn refunded its mint); surplus **107,212,750 sompi** = genesis 100M + 3,522,750
swap fees + 23,690,000 liquidation share − 20,000,000 governance spend. Oracle epoch 6, live.
Lessons learned live: the driver must mirror the contract's one-hour-per-refresh rate window
and ceiling rounding on swap_in; a KIP-9 storage-mass floor rejects small (2M-sompi) payouts,
so the surplus spend ran after the liquidation topped it up.

### 2026-11-14 (oracle Stage 1) — five-operator signed-print oracle, re-genesis + live demos

Stage 1 changes the oracle template (five operators, median of three offline-signed
prints with signed-at DAA, 3-signer rotation), so the whole family was re-created in the
10-step order. All five genesis covids reproduced by `argentc genesis verify
--require-argent` (argent 0cf5b30). Phase 5 evidence moved to `evidence/phase5/`.

| Step | covid / result | txid |
|---|---|---|
| Oracle genesis (5 operators, 40 c/KAS) | `f5bffe9e…` verified ✓ | `7166837e…` |
| PSM genesis (unwired) | `3a07300f…` verified ✓ | `37fe6ff9…` |
| Surplus genesis | `07fd6a2d…` verified ✓ | `68d9cff2…` |
| Budget genesis (unwired, $50k/day) | `8cea88e0…` verified ✓ | `f2593c1d…` |
| Authority genesis (192-byte config) | `adda24f8…` verified ✓ | `5a18b649…` |
| Wire PSM / wire budget | | `2e97ed9b…` / `e2ff264c…` |
| Vault genesis | `2d7aba9f…` | `0ed5db27…` |
| **refresh from signed prints**: operators 0/2/4 printed 4100/4120/4090 → median 4100 | relayed; no operator signed the tx | `a20b5c40…` |
| out-of-band print set 4100/4110/4600 (spread > 3%) | **refused by the covenant** (script VerifyError, not submitted) | — |
| **set_member**: slot 4 → fresh key, signed by operators 0/1/2 | rotation, epoch bumped | `9629c0e1…` |
| refresh with the NEW slot-4 key: operators 1/3/4 printed 4150/4140/4160 | median 4150; mint_price 4100 → 4108 (minutes of rate) | `2fdae10b…` |
| **budget set_limit** (gov 2-of-3): $50,000 → $40,000/day | available clamped to the new limit | `ad01eaf9…` |
| mint 200c (budget-metered) | priced at mint_price 4108, not raw 4150 | `54cfc73b…` |

Operating a refresh: each operator signs `blake2b(oracle_covid ‖ epoch ‖ price ‖ t)` with
`t` = the current DAA score (here: the funding input's confirmation, which doubles as the
clock input); the relayer runs `STAGE=refresh OPS=a,b,c PRICES=pa,pb,pc`. Rotation:
`STAGE=setmember SLOT=s NEW_KEY=name SIGNERS=a,b,c` (signers exclude `s`). Rule for
operators: one print per epoch, relayed promptly, plus a regular heartbeat — the newest
unrelayed print set can always be relayed later (a lower-bound clock can't prove "too old").
Retired-key refusal is covered by `rotated_out_key_can_no_longer_print` (a driver dry run
can't show it: the driver models the input state from its own operator list).
