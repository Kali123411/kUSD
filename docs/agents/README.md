# kUSD for agent developers

How an agent holds kUSD, pays a service with it through k402, verifies the settlement and the covenant state
against a TN10 node, and sells a service of its own. Everything here runs on **Kaspa testnet-10**.

**TN10 testnet research software. Not audited. Not a product. Not for real value.** Not financial advice.

## 0. The pieces

| Piece | What it is | Where |
| --- | --- | --- |
| kUSD | USD cents held as covenant state in boxes owned by an x-only key | this repo; live state at https://kaspa-app.vercel.app/kusd |
| `kusd_pay` | the wallet binary (`family · balance · buy · send · verify · claim`) the Python client drives; built from the kUSD harness (it ships in the harness from the 2026-11-16 family onward, after this public snapshot) | interface documented in the k402 repo (`DESIGN-kusd-market.md`) |
| k402 | the rails: HTTP 402 pay-per-call, the `kusd-utxo` scheme, kUSD as an x402 v2 asset, `KusdPayer`, `SpendPolicy` | `pip install k402` · https://github.com/Kali123411/k402 |
| k402-mcp | the same for MCP clients: `pay_kusd`, `kusd_balance`, `kusd_spend_status`, `registry_search` | https://github.com/Kali123411/k402-mcp |
| the market | the k402 registry at `https://market.kaspa-402.org` and its page | https://kaspa-app.vercel.app/kusd/market |

## 1. Hold kUSD

A kUSD box is owned by a secp256k1 x-only key; the same key is a Kaspa address for the KAS that pays fees and
sits in each box (1.5 KAS per holder box on the current family). Two ways to get a funded key on testnet-10:

- **Browser:** https://kaspa-app.vercel.app/kusd/app creates a sealed keystore, takes TKAS from the faucet,
  buys kUSD from the PSM and sends it. The same key is an agent on the market page.
- **Code:** generate a 32-byte secret, fund its `kaspatest:` address with TKAS (https://faucet-tn10.kaspanet.io/),
  then buy kUSD through the PSM:

```bash
export KUSD_KEY_FILE=~/.kusd/agent.key   # 64 hex, mode 600, never printed
export KUSD_AUTHORITY=<the kUSD authority covenant id>   # pins the family: see §4
export KUSD_NETWORK=testnet-10 KUSD_RELAY_URL=https://kusd.kaspa-402.org
kusd_pay balance            # {"kusd_cents": 0, "kas_sompi": …, "address": "kaspatest:…", "xonly": "…"}
kusd_pay buy --cents 100    # swap KAS for 1.00 kUSD through the PSM (fee quoted first)
```

## 2. Pay a service through k402

A kUSD provider answers an unpaid request with HTTP 402. Its `PAYMENT-REQUIRED` header (x402 v2, base64 JSON)
carries a requirement with `scheme: "exact"`, `asset: <the kUSD authority covenant id>`, `amount: "<cents>"`,
`payTo: <the provider's listed key tweaked by the offer's payment_id>` and `extra.binding: "kusd-holder-v1"`.
The payer builds a kUSD box of exactly those cents to that key and retries with `PAYMENT-SIGNATURE` carrying the
creating txid. Spec: https://github.com/Kali123411/k402/blob/main/scheme_exact_kusd.md

```python
# pip install k402   (Python 3.10+; kusd_pay on PATH or KUSD_PAY_BIN)
import asyncio, os
from k402 import KusdPayer, KusdWallet, SpendLedger, SpendPolicy

wallet = KusdWallet(os.environ["KUSD_PAY_BIN"], key_file=os.environ["KUSD_KEY_FILE"],
                    authority=os.environ["KUSD_AUTHORITY"], network="testnet-10",
                    relay_url="https://kusd.kaspa-402.org")
# the operator's bounds: the agent cannot loosen them from a call
policy = SpendPolicy.from_dict({"max_per_call_cents": 25, "max_total_cents": 500,
                                "max_window_cents": 200, "max_window_calls": 20,
                                "max_window_topup_cents": 100, "max_window_failures": 2})
payer = KusdPayer(wallet, registry_url="https://market.kaspa-402.org", network="testnet-10",
                  policy=policy, ledger=SpendLedger("~/.kusd/spend.db"))

async def main():
    route = await payer.pay_best("summarize", json_body={"text": "Kaspa is a proof-of-work blockDAG…", "max_words": 40})
    res = route.result
    print(res.response.json(), res.txid, res.cents, res.wire)      # the answer, the box, the price, "x402"
    print(payer.spend_status()["remaining"])                        # what the operator's policy has left

asyncio.run(main())
```

Before any box is built the client checks the quote: our kUSD family (`asset`), our network, a price inside
the operator's ceiling, and `payTo == derive_payee(listed_key, payment_id)` recomputed locally, so a hijacked
endpoint cannot redirect the money. From an MCP client the same call is the `k402-mcp` tool
`pay_kusd("summarize", {...})`, bounded by `KUSD_SPEND_POLICY`.

## 3. Verify a settlement

A kUSD payment is not a receipt: it is a covenant output a node can check.

- **With the wallet:** `kusd_pay verify --txid <txid> --to <payTo> --cents <cents> --authority $KUSD_AUTHORITY --since-daa <offer daa>`
  answers `{"ok": true, "index": …}` only if an unspent box of exactly those cents, owned by that key and carrying
  the family's covenant id, exists at that transaction.
- **By hand:** compute the box address from its state `{amount, owner, owner_scheme, borrow_scheme, borrow_guard, ext}`
  with the kusd-client (`box_address` in the WASM, `KusdState::holder` in Rust), then check the outpoint on a node:
  its script public key must be that P2SH and its covenant id must be the family's authority id. The
  [protocol README](../../contracts/v2/README.md) describes the state layout; the harness tests recompute
  addresses this way.
- **The market's record:** `GET https://market.kaspa-402.org/registry/activity?limit=50` lists settlements the
  registry verified on its own node (txid, box index, payee, cents, capability, time) — the source of the
  reputation figures on the market page.

## 4. Read the covenant ids

The deploy runbook ([contracts/v2/deploy/README.md](../../contracts/v2/deploy/README.md)) lists every family's
covenant ids and the transactions that created them; the live page publishes the current family's ids in
https://kaspa-app.vercel.app/kusd/snapshot.json (`covenants.<name>.covid`). The **authority** id is the token's
on-chain identity: it is the `asset` of every kUSD x402 requirement and the `KUSD_AUTHORITY` the wallet pins, so
a relay or a provider can never substitute another family's boxes. Covenant state is a script hash: to check a
published value, compile the template with that state and compare the hash with the output on chain.

## 5. Sell a service for kUSD

```python
# a FastAPI endpoint priced at 5¢ of kUSD a call (KAS still accepted), on both wires
from fastapi import Depends, FastAPI
from k402 import K402, KusdWallet, NodeBackend

k402 = K402(address_provider=..., backend=NodeBackend(...), network="testnet-10",
            kusd=KusdWallet("kusd_pay", key_file="~/.kusd/provider.key", authority=AUTHORITY, network="testnet-10"),
            kusd_price_cents=5)
app = FastAPI(); k402.install(app)

@app.post("/summarize")
async def summarize(body: dict, payment=Depends(k402.paid(sompi=3_000_000, description="summarize", cents=5))):
    ...   # verified: the box exists on your node; report it to the registry while it is unspent
```

List it with a listing signed by the same key (`POST https://market.kaspa-402.org/registry/list`, 10¢ kUSD fee
paid through k402 — `examples/kusd_list.py` in the k402 repo does both), and report each verified payment to
`/registry/settled` so your reputation is the kUSD a node has seen you settle.

## Operator controls, in one place

`SpendPolicy` (k402 `DESIGN-kusd-spend-controls.md`): per-call ceiling, lifetime and per-window kUSD, calls per
window, PSM top-up cap (`0` = never convert KAS), stop after N unserved payments, allowed capabilities and
payees, a kill switch (`k402-spend --ledger … freeze`). The ledger is sqlite, reserved before any box is built,
so a restart never resets a budget. The agent has no tool that edits any of it.

Today all five oracle operator keys are held by the deployer; independent operators are a pre-mainnet gate.
