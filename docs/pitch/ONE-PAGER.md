# kUSD — the covenant-native USD stablecoin for Kaspa, built on L1

*TN10 research software: not audited, not a product, not for real value — yet.
That "yet" is what this page is about.*

## What exists, today, on testnet-10

A complete dollar system living entirely in Kaspa covenants — no bridge, no L2,
no trusted issuer:

- **USD-denominated kUSD** (KCC-20 conformant: your wallet's token standard),
  minted against KAS collateral at ≥175% in permissionless vaults.
- **A redemption reserve (peg floor):** burn kUSD, get $1 of KAS at the
  oracle price — permissionless, paid from the reserve's KAS while it
  lasts, and governance can *never* block redemption, only cap growth. Enforced by consensus, not policy.
- **Liquidations** with a keeper incentive (110% of debt) and a protocol split
  (3%) — atomic, in one transaction, at under 9% of a block's compute budget.
- **A fee switch that is OFF** — and demonstrated: governance turned a 25 bps
  spread on, two swaps routed 5M sompi of real revenue into the on-chain
  surplus covenant, governance turned it off, then withdrew revenue by 2-of-3
  with a consensus-pinned destination. Tx `727025a8…` is a fee landing in the
  protocol's treasury with no human in the loop.

Every protocol entry has been executed under real consensus across 50
transactions and two full deployment campaigns. The books balance to the cent
on-chain: at the end of the campaign the supply authority held the genesis
supply minus exactly the 450 cents outstanding, and the treasury held exactly
its accounted fees.

## What's deliberately NOT on

Fees (off until audit + governance), mainnet (TN10 only), and trust-me claims:
the protocol has survived four adversarial security reviews that produced real,
fixed, regression-tested attack transactions — but **no external audit yet**.
That is the first thing funding buys.

## What community funding buys, in order

1. **External audits** (two firms: covenant + economic).
2. **Oracle decentralization** — five independent operators with a signed-print median are live on testnet; next, a miner-voted price bounds and then replaces them.
3. **Mainnet beta under hard caps** — tiny ceiling, fees off, real KAS, bounded risk.
4. **Keeper tooling** — open-source liquidation bots (the 110% split pays them).
5. **Stability fees** — the DAA-based accrual covenant (designed, not built).

## Who it is for: agents

Autonomous software can't open a bank account, pass KYC, or hold a card. kUSD is the **money** layer of an
agent-native marketplace on Kaspa L1: **k402** (Kaspa x402 v2) is the rails — HTTP 402 pay-per-call with no
account or API key — and the **kUSD agent market** is where agents find, buy from and sell to each other,
with reputation that is settled kUSD a node has verified and `SpendPolicy` limits a human operator sets.
It is live on testnet-10: agents pay 0.05 kUSD a call for `summarize`, each payment a covenant box a node
can check. Humans supervise; agents transact. (kaspa-402.org · kaspa-app.vercel.app/kusd/market)

## Fund it

**`kaspa:qre88nev5r8y3knz4jja6g08tpstqaukumump6q2xh0da5zy3j5sulvmlwy5c`**

Held by the project founder in a Kaspa wallet; spending is reported publicly against
the roadmap above. This is a donation to fund development — not an investment,
not a token sale, and it confers no claim.

## Verify every word

- Code + tests + whitepaper: https://github.com/Kali123411/kUSD
- Every cited transaction: archived serialized in `docs/pitch/evidence/`
  (verifiable against the node's own covenant engine, even after TN10 resets)
- 116 tests including every review attack as a regression:
  `cargo test --release`
- Contact: `[OWNER: contact handles]`
