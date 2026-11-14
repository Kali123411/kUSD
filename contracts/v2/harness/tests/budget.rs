// Phase 5 Task 3: the global mint budget — token bucket, governance, wiring,
// and the grief shapes: a burn tx (repay / swap_out / close) co-spending the
// budget to drain it must be rejected, and `meter` can never run standalone.

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{
    Hash,
    tx::{CovenantBinding, ScriptPublicKey, UtxoEntry},
};
use kusd_v2_harness::{budget_state, demo_keypair, demo_outpoint, gate_setup, meter, meter_expect_err, protocol_runtime, sign_input};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const TOMBSTONE: u64 = 100_000_000;
const KUSD_COVID: [u8; 32] = [0x42; 32];
const ORACLE_COVID: [u8; 32] = [0x07; 32];
const PSM_COVID: [u8; 32] = [0x66; 32];
const SURPLUS_COVID: [u8; 32] = [0x77; 32];
const BUDGET_COVID: [u8; 32] = [0x88; 32];
const VAULT_COVID: [u8; 32] = [0x99; 32];
const ZERO32: [u8; 32] = [0u8; 32];
const LIMIT: i64 = 1_000_000_000;
const PRICE: i64 = 4_000;

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

fn kusd_state(amount: i64, owner: &[u8], scheme: u8, ext: &[u8]) -> BTreeMap<String, ArtifactValue> {
    state! {
        amount: amount,
        owner: owner.to_vec(),
        owner_scheme: scheme,
        borrow_scheme: 0u8,
        borrow_guard: ZERO32.to_vec(),
        extension_commitment: ext.to_vec(),
    }
}

fn vault_state(collateral: i64, debt: i64) -> BTreeMap<String, ArtifactValue> {
    state! {
        owner: xonly(1),
        collateral: collateral,
        debt: debt,
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: ORACLE_COVID.to_vec(),
        surplus_id: SURPLUS_COVID.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    }
}

fn psm_state(minted: i64) -> BTreeMap<String, ArtifactValue> {
    state! {
        ceiling_cents: 100_000i64,
        minted_cents: minted,
        spread_bps: 0i64,
        g0: xonly(20),
        g1: xonly(21),
        g2: xonly(22),
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: ORACLE_COVID.to_vec(),
        surplus_id: SURPLUS_COVID.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    }
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

struct Built {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<UtxoEntry>,
}

fn expect_rejected(result: Result<Built, String>, expect: &str) -> String {
    let err = match result {
        Err(build_err) => build_err,
        Ok(mut built) => meter_expect_err(&mut built.tx, built.entries),
    };
    assert!(err.contains(expect), "rejected for the wrong reason: wanted '{expect}' in '{err}'");
    err
}

fn emission_call(states: ArtifactValue, psm_gate: bool) -> EntryCall<'static> {
    EntryCall::new("emission").args_with(move |_tx, _idx| {
        let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
        let (plen, slen) = if psm_gate { (gate.psm_prefix_len, gate.psm_suffix_len) } else { (gate.vault_prefix_len, gate.vault_suffix_len) };
        vec![
            ArgValue::Value(states.clone()),
            ArgValue::Value(ArtifactValue::Int(0)),
            ArgValue::Value(ArtifactValue::Int(plen)),
            ArgValue::Value(ArtifactValue::Int(slen)),
            ArgValue::Value(ArtifactValue::Bytes(gate.vault_template.clone())),
            ArgValue::Value(ArtifactValue::Bytes(gate.psm_template.clone())),
            ArgValue::Value(ArtifactValue::Bytes(gate.oracle_covid.clone())),
            ArgValue::Value(ArtifactValue::Bytes(gate.psm_covid.clone())),
            ArgValue::Value(ArtifactValue::Bytes(gate.surplus_covid.clone())),
            ArgValue::Value(ArtifactValue::Bytes(gate.budget_covid.clone())),
            ArgValue::Value(ArtifactValue::Bool(psm_gate)),
        ]
    })
}

fn delegator(key: u8) -> EntryCall<'static> {
    EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(key))))])
}

#[derive(Clone, Copy)]
enum BudgetMode {
    Absent,
    /// co-spent under `meter(d)` (an issuance entry — must be refused in a burn tx)
    Meter(i64),
    /// co-spent under `credit(r)`: available `avail_in` -> pinned `avail_out`
    Credit(i64, i64, i64),
}

/// The budget box co-spent under `credit(r)`, clock = its own input index.
fn add_budget_credit<'a>(context: TxContext<'a>, builder: &TxBuilder<'_>, r: i64, avail_in: i64, avail_out: i64, idx: u16) -> (TxContext<'a>, UtxoEntry) {
    let covid = Hash::from_bytes(BUDGET_COVID);
    let b_in = budget_state(LIMIT, avail_in, 0, KUSD_COVID);
    let b_out = budget_state(LIMIT, avail_out, 0, KUSD_COVID);
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), DUST, 0, false, Some(covid)).expect("budget utxo");
    let i = idx as i64;
    let context = context
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(r)), ArgValue::Value(ArtifactValue::Int(i))]),
            demo_outpoint(0xBD, idx as u32),
            utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, CovenantBinding::new(idx, covid), DUST);
    (context, utxo)
}

/// The budget box co-spent under `meter(d)`, clock = its own input index.
fn add_budget_meter<'a>(context: TxContext<'a>, builder: &TxBuilder<'_>, d: i64, idx: u16, kusd_id: [u8; 32]) -> (TxContext<'a>, UtxoEntry) {
    let covid = Hash::from_bytes(BUDGET_COVID);
    let b_in = budget_state(LIMIT, LIMIT, 0, kusd_id);
    let b_out = budget_state(LIMIT, LIMIT - d, 0, kusd_id);
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), DUST, 0, false, Some(covid)).expect("budget utxo");
    let i = idx as i64;
    let context = context
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(d)), ArgValue::Value(ArtifactValue::Int(i)), ArgValue::Value(ArtifactValue::Bytes(xonly(1)))]
            }),
            demo_outpoint(0xBB, idx as u32),
            utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, CovenantBinding::new(idx, covid), DUST);
    (context, utxo)
}

// --- the budget on its own ----------------------------------------------------

fn build_standalone_meter(kusd_id: [u8; 32]) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let (context, utxo) = add_budget_meter(TxContext::new(), &builder, 1_000, 0, kusd_id);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

#[test]
fn meter_standalone_rejected() {
    // no authority co-spent: anyone could drain the bucket (a minting DoS)
    let err = expect_rejected(build_standalone_meter(KUSD_COVID), "observe `kusd` expects 1 inputs");
    println!("standalone meter rejected: {err}");
}

#[test]
fn meter_unwired_rejected() {
    let err = expect_rejected(build_standalone_meter(ZERO32), "observe `kusd` expects 1 inputs");
    println!("unwired meter rejected: {err}");
}

fn build_gov(entry: &str, b_in: BTreeMap<String, ArtifactValue>, b_out: BTreeMap<String, ArtifactValue>, arg0: ArtifactValue, keys: (u8, u8)) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let covid = Hash::from_bytes(BUDGET_COVID);
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), DUST, 0, false, Some(covid)).expect("budget utxo");
    let (ka, kb) = (demo_keypair(keys.0), demo_keypair(keys.1));
    let set_limit = entry == "set_limit";
    let context = TxContext::new()
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new(entry).args_with(move |tx, input_idx| {
                let mut v = vec![
                    ArgValue::Value(arg0.clone()),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ka))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kb))),
                ];
                if set_limit {
                    v.push(ArgValue::Value(ArtifactValue::Int(0))); // clock: the budget's own input
                }
                v
            }),
            demo_outpoint(0xBC, 0),
            utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, CovenantBinding::new(0, covid), DUST);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

#[test]
fn set_limit_2of3_clamps_available_and_metered() {
    // cut the limit from 1e9 to 5e6: the balance is clamped at once
    let mut built = build_gov(
        "set_limit",
        budget_state(LIMIT, LIMIT, 0, KUSD_COVID),
        budget_state(5_000_000, 5_000_000, 0, KUSD_COVID),
        ArtifactValue::Int(5_000_000),
        (20, 22),
    )
    .expect("set_limit builds");
    let report = meter(&mut built.tx, built.entries);
    println!("BUDGET set_limit: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn set_limit_unclamped_balance_rejected() {
    let err = expect_rejected(
        build_gov("set_limit", budget_state(LIMIT, LIMIT, 0, KUSD_COVID), budget_state(5_000_000, LIMIT, 0, KUSD_COVID), ArtifactValue::Int(5_000_000), (20, 22)),
        "script ran, but verification failed",
    );
    println!("unclamped balance rejected: {err}");
}

#[test]
fn set_limit_wrong_key_rejected() {
    let err = expect_rejected(
        build_gov("set_limit", budget_state(LIMIT, LIMIT, 0, KUSD_COVID), budget_state(5_000_000, 5_000_000, 0, KUSD_COVID), ArtifactValue::Int(5_000_000), (20, 29)),
        "script ran, but verification failed",
    );
    println!("set_limit wrong key rejected: {err}");
}

#[test]
fn wire_once_ok_and_rewire_rejected() {
    let mut built = build_gov("wire", budget_state(LIMIT, LIMIT, 0, ZERO32), budget_state(LIMIT, LIMIT, 0, KUSD_COVID), ArtifactValue::Bytes(KUSD_COVID.to_vec()), (20, 22))
        .expect("wire builds");
    meter(&mut built.tx, built.entries);
    let err = expect_rejected(
        build_gov("wire", budget_state(LIMIT, LIMIT, 0, KUSD_COVID), budget_state(LIMIT, LIMIT, 0, [0x55; 32]), ArtifactValue::Bytes(vec![0x55; 32]), (20, 22)),
        "script ran, but verification failed",
    );
    println!("re-wire rejected: {err}");
}

// --- grief: burn txs co-spending the budget ------------------------------------

/// Full repay of a 200c vault; optionally co-spends the budget under meter.
fn build_repay(mode: BudgetMode) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let vault_covid = Hash::from_bytes(VAULT_COVID);
    let gov = xonly(5);
    let auth_in = kusd_state(999_800, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(1_000_000, &gov, 0x10, &gate.ext);
    let holder = kusd_state(200, &xonly(1), 0x00, &gate.ext);
    let v_in = vault_state(1_000_000_000, 200);
    let v_out = vault_state(1_000_000_000, 0);
    let v_utxo = builder.covenant_utxo("vault_app::Vault", v_in.clone(), TOMBSTONE + 1_000_000_000, 0, false, Some(vault_covid)).expect("vault");
    let a_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth");
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid)).expect("holder");
    let owner_kp = demo_keypair(1);
    let states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            v_in,
            EntryCall::new("repay").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(200)),
                    ArgValue::Value(ArtifactValue::Int(1_000_000_000)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            demo_outpoint(0xC1, 0),
            v_utxo.clone(),
            0,
        )
        .actor_input("kusd_app::Kusd", auth_in, emission_call(states, false), demo_outpoint(0xC2, 0), a_utxo.clone(), 0)
        .actor_input("kusd_app::Kusd", holder, delegator(1), demo_outpoint(0xC3, 0), h_utxo.clone(), 0)
        .actor_output("vault_app::Vault", v_out, CovenantBinding::new(0, vault_covid), TOMBSTONE + 1_000_000_000)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), 2 * DUST);
    let mut entries = vec![v_utxo, a_utxo, h_utxo];
    let context = match mode {
        BudgetMode::Absent => context,
        BudgetMode::Meter(d) => {
            let (c, u) = add_budget_meter(context, &builder, d, 3, KUSD_COVID);
            entries.push(u);
            c
        }
        BudgetMode::Credit(r, a_in, a_out) => {
            let (c, u) = add_budget_credit(context, &builder, r, a_in, a_out, 3);
            entries.push(u);
            c
        }
    };
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries })
}

#[test]
fn repay_credits_budget_ok_and_metered() {
    // review I-2 (net metering): a 200c burn refunds 200c of issuance headroom
    let mut built = build_repay(BudgetMode::Credit(200, LIMIT - 500, LIMIT - 300)).expect("repay with budget credit builds");
    let report = meter(&mut built.tx, built.entries);
    println!("REPAY+CREDIT: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn repay_credit_capped_at_limit() {
    // a full bucket stays full (no banking headroom above the daily limit)
    let mut built = build_repay(BudgetMode::Credit(200, LIMIT, LIMIT)).expect("capped credit builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn repay_credit_overclaim_rejected() {
    // the budget may only be credited the cents actually burned
    let err = expect_rejected(build_repay(BudgetMode::Credit(200, LIMIT - 500, LIMIT - 100)), "script ran, but verification failed");
    println!("credit over-claim rejected: {err}");
}

#[test]
fn repay_without_budget_rejected() {
    // net metering: every burn must refund the budget
    let err = expect_rejected(build_repay(BudgetMode::Absent), "observe `budget` expects 1 inputs");
    println!("unmetered burn rejected: {err}");
}

#[test]
fn repay_co_spending_budget_meter_rejected() {
    // a 200c burn running the budget's ISSUANCE entry to drain it
    let err = expect_rejected(build_repay(BudgetMode::Meter(LIMIT)), "observe `kusd` expects 1 inputs");
    println!("repay+meter grief rejected: {err}");
}

/// PSM swap_out (redemption); optionally co-spends the budget under meter.
fn build_swap_out(mode: BudgetMode) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let c: i64 = 400;
    let gov = xonly(5);
    let auth_in = kusd_state(999_000, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(999_000 + c, &gov, 0x10, &gate.ext);
    let holder = kusd_state(c, &xonly(7), 0x00, &gate.ext);
    let ora = kusd_v2_harness::oracle_state_v2(PRICE);
    let kas_out = kusd_v2_harness::sompi_of(c, PRICE) as u64;
    let psm_value_in = TOMBSTONE + 2_000_000_000;
    let p_utxo = builder.covenant_utxo("psm_app::Psm", psm_state(c), psm_value_in, 0, false, Some(psm_covid)).expect("psm");
    let a_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth");
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid)).expect("holder");
    let o_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle");
    let burner = demo_keypair(7);
    let redeemer = xonly(7);
    let mut payout = vec![0x20];
    payout.extend_from_slice(&redeemer);
    payout.push(0xac);
    let states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_state(c),
            EntryCall::new("swap_out").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner))),
                    ArgValue::Value(ArtifactValue::Int(4)),
                ]
            }),
            demo_outpoint(0xD1, 0),
            p_utxo.clone(),
            0,
        )
        .actor_input("kusd_app::Kusd", auth_in, emission_call(states, true), demo_outpoint(0xD2, 0), a_utxo.clone(), 0)
        .actor_input("kusd_app::Kusd", holder, delegator(7), demo_outpoint(0xD3, 0), h_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xD4, 0), o_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_state(0), CovenantBinding::new(0, psm_covid), psm_value_in - kas_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), 2 * DUST)
        .output(ScriptPublicKey::from_vec(0, payout), None, kas_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(3, oracle_covid), DUST);
    let mut entries = vec![p_utxo, a_utxo, h_utxo, o_utxo];
    let context = match mode {
        BudgetMode::Absent => context,
        BudgetMode::Meter(d) => {
            let (cx, u) = add_budget_meter(context, &builder, d, 4, KUSD_COVID);
            entries.push(u);
            cx
        }
        BudgetMode::Credit(r, a_in, a_out) => {
            let (cx, u) = add_budget_credit(context, &builder, r, a_in, a_out, 4);
            entries.push(u);
            cx
        }
    };
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries })
}

#[test]
fn swap_out_credits_budget_ok() {
    // a swap_in/swap_out round trip now nets to zero budget (review I-2)
    let mut built = build_swap_out(BudgetMode::Credit(400, LIMIT - 400, LIMIT)).expect("swap_out with budget credit builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn swap_out_co_spending_budget_meter_rejected() {
    let err = expect_rejected(build_swap_out(BudgetMode::Meter(LIMIT)), "observe `kusd` expects 1 inputs");
    println!("swap_out+meter grief rejected: {err}");
}

// --- review I-1: a plain holder transfer must never meter the budget --------------

#[test]
fn holder_transfer_cannot_meter_budget() {
    // reviewer PoC: any kUSD box (here 0 cents) self-transferred alongside meter(LIMIT)
    // used to drain the whole daily budget for a tx fee — the budget now
    // authenticates the AUTHORITY and binds d to its supply change
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let me = xonly(9);
    let h = kusd_state(0, &me, 0x00, &gate.ext);
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", h.clone(), DUST, 0, false, Some(kusd_covid)).expect("holder");
    let kp = demo_keypair(9);
    let states = ArtifactValue::Array(vec![obj(h.clone())]);
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            h.clone(),
            EntryCall::new("transfer").args_with(move |tx, idx| vec![ArgValue::Value(states.clone()), ArgValue::Value(ArtifactValue::Bytes(kusd_v2_harness::owner_witness_p2pk(tx, idx, &kp)))]),
            demo_outpoint(0xE1, 0),
            h_utxo.clone(),
            0,
        )
        .actor_output("kusd_app::Kusd", h, CovenantBinding::new(0, kusd_covid), DUST);
    let (context, b_utxo) = add_budget_meter(context, &builder, LIMIT, 1, KUSD_COVID);
    let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries: vec![h_utxo, b_utxo] });
    let err = expect_rejected(result, "observe `kusd` expects 2 outputs");
    println!("holder-transfer budget drain rejected: {err}");
}

#[test]
fn holder_split_mimicking_mint_cannot_meter_budget() {
    // a holder transfer split [1000 - d, d] has the mint's kUSD shape (1 in, 2 out)
    // and conserves amounts, so it satisfies the budget's observe pins — only the
    // authority check (owner_scheme 0x10) stops it from draining the bucket by d
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let d: i64 = 600;
    let me = xonly(9);
    let recipient = xonly(1);
    let h_in = kusd_state(1_000, &me, 0x00, &gate.ext);
    let keep = kusd_state(1_000 - d, &me, 0x00, &gate.ext);
    let sent = kusd_state(d, &recipient, 0x00, &gate.ext);
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", h_in.clone(), 2 * DUST, 0, false, Some(kusd_covid)).expect("holder");
    let kp = demo_keypair(9);
    let states = ArtifactValue::Array(vec![obj(keep.clone()), obj(sent.clone())]);
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            h_in,
            EntryCall::new("transfer").args_with(move |tx, idx| vec![ArgValue::Value(states.clone()), ArgValue::Value(ArtifactValue::Bytes(kusd_v2_harness::owner_witness_p2pk(tx, idx, &kp)))]),
            demo_outpoint(0xE3, 0),
            h_utxo.clone(),
            0,
        )
        .actor_output("kusd_app::Kusd", keep, CovenantBinding::new(0, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", sent, CovenantBinding::new(0, kusd_covid), DUST);
    let (context, b_utxo) = add_budget_meter(context, &builder, d, 1, KUSD_COVID);
    let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries: vec![h_utxo, b_utxo] });
    let err = expect_rejected(result, "script ran, but verification failed");
    println!("holder split mimicking a mint rejected: {err}");
}
