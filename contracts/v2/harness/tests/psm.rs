// Phase 2 Task 2: the PSM — a USD-priced redemption reserve (the peg floor).
// Tx shapes:
//   swap_in:     [psm, auth(emission,psm-gate), oracle] -> [psm', auth', emitted, oracle']
//   swap_out:    [psm, auth(emission), holder(join), oracle] -> [psm', auth', payout(P2PK), oracle']
//   set_ceiling: [psm, auth(emission, frozen family)] -> [psm', auth']
// Every PSM entry observes and pins the kusd group (the emission-gate invariant).

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{
    Hash,
    tx::{CovenantBinding, ScriptPublicKey},
};
use kusd_v2_harness::{budget_state, demo_keypair, demo_outpoint, gate_setup, meter, meter_expect_err, protocol_runtime, sign_input};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const TOMBSTONE: u64 = 100_000_000;
const KUSD_COVID: [u8; 32] = [0x42; 32];
const FAKE_KUSD_COVID: [u8; 32] = [0x55; 32];
const ORACLE_COVID: [u8; 32] = [0x07; 32];
const PSM_COVID: [u8; 32] = [0x66; 32];
const SURPLUS_COVID: [u8; 32] = [0x77; 32];
const BUDGET_COVID: [u8; 32] = [0x88; 32];
const ZERO32: [u8; 32] = [0u8; 32];

const PRICE: i64 = 4_000; // 1e-4 USD/KAS: $0.40 // cents per KAS

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

fn p2pk_spk(owner: &[u8]) -> ScriptPublicKey {
    let mut script = vec![0x20];
    script.extend_from_slice(owner);
    script.push(0xac);
    ScriptPublicKey::from_vec(0, script)
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

thread_local! {
    static ORA_STATUS: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

fn oracle_state(price: i64) -> BTreeMap<String, ArtifactValue> {
    kusd_v2_harness::oracle_state_full(price, price, price, 0, ORA_STATUS.with(|s| s.get()))
}

fn with_status<T>(status: i64, f: impl FnOnce() -> T) -> T {
    ORA_STATUS.with(|s| s.set(status));
    let r = f();
    ORA_STATUS.with(|s| s.set(0));
    r
}

fn psm_state(ceiling: i64, minted: i64, kusd_covid: [u8; 32], oracle_covid: [u8; 32]) -> BTreeMap<String, ArtifactValue> {
    psm_state_full(ceiling, minted, 0, kusd_covid, oracle_covid, SURPLUS_COVID)
}

fn psm_state_full(ceiling: i64, minted: i64, spread: i64, kusd_covid: [u8; 32], oracle_covid: [u8; 32], surplus_covid: [u8; 32]) -> BTreeMap<String, ArtifactValue> {
    state! {
        ceiling_cents: ceiling,
        minted_cents: minted,
        spread_bps: spread,
        g0: xonly(20),
        g1: xonly(21),
        g2: xonly(22),
        kusd_id: kusd_covid.to_vec(),
        oracle_id: oracle_covid.to_vec(),
        surplus_id: surplus_covid.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    }
}

fn surplus_state() -> BTreeMap<String, ArtifactValue> {
    state! { g0: xonly(20), g1: xonly(21), g2: xonly(22), kusd_id: KUSD_COVID.to_vec() }
}

const BUDGET_LIMIT: i64 = 1_000_000_000;

/// Append the global mint budget as the NEXT input (index `idx`, also the
/// clock: its own DAA score 0) metering `d` cents, plus its continuation.
fn add_budget<'a>(context: TxContext<'a>, builder: &TxBuilder<'_>, d: i64, idx: u16) -> (TxContext<'a>, kaspa_consensus_core::tx::UtxoEntry) {
    let budget_covid = Hash::from_bytes(BUDGET_COVID);
    let b_in = budget_state(BUDGET_LIMIT, BUDGET_LIMIT, 0, KUSD_COVID);
    let b_out = budget_state(BUDGET_LIMIT, BUDGET_LIMIT - d, 0, KUSD_COVID);
    let b_utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), DUST, 0, false, Some(budget_covid)).expect("budget utxo");
    let i = idx as i64;
    let context = context
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(d)), ArgValue::Value(ArtifactValue::Int(i)), ArgValue::Value(ArtifactValue::Bytes(xonly(3)))]),
            demo_outpoint(0xBB, idx as u32),
            b_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, CovenantBinding::new(idx, budget_covid), DUST);
    (context, b_utxo)
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

struct Built {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<kaspa_consensus_core::tx::UtxoEntry>,
}

/// Assert rejection AND the expected failing check (review I2 discipline).
fn expect_rejected(result: Result<Built, String>, expect: &str) -> String {
    let err = match result {
        Err(build_err) => build_err,
        Ok(mut built) => meter_expect_err(&mut built.tx, built.entries),
    };
    assert!(err.contains(expect), "rejected for the wrong reason: wanted '{expect}' in '{err}'");
    err
}

fn emission_args(states: ArtifactValue, gate_idx: i64, psm_gate: bool) -> Vec<ArgValue> {
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let (plen, slen) = if psm_gate { (gate.psm_prefix_len, gate.psm_suffix_len) } else { (gate.vault_prefix_len, gate.vault_suffix_len) };
    vec![
        ArgValue::Value(states),
        ArgValue::Value(ArtifactValue::Int(gate_idx)),
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
}

/// swap_in of `c` cents at `price`: reserve gains c*1e8/price sompi.
fn build_swap_in(c: i64, ceiling: i64, minted: i64, psm_kusd_covid: [u8; 32], psm_oracle_byte: u8, psm_covid_byte: u8) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes([psm_oracle_byte; 32]);
    let psm_covid = Hash::from_bytes([psm_covid_byte; 32]);

    let user = xonly(3);
    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount - c, &gov, 0x10u8, &gate.ext);
    let emitted = kusd_state(c, &user, 0u8, &gate.ext);
    let ora = oracle_state(PRICE);
    let psm_in = psm_state(ceiling, minted, psm_kusd_covid, [psm_oracle_byte; 32]);
    let psm_out = psm_state(ceiling, minted + c, psm_kusd_covid, [psm_oracle_byte; 32]);

    let kas_in = (kusd_v2_harness::sompi_of_ceil(c, PRICE)) as u64;
    let psm_value_in: u64 = TOMBSTONE + 2_000_000_000;
    let psm_value_out: u64 = psm_value_in + kas_in;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let user_arg = user.clone();

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Bytes(user_arg.clone())), ArgValue::Value(ArtifactValue::Int(3))]
            }),
            demo_outpoint(0x61, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0x62, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x63, 0), ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, oracle_covid), DUST);
    let (context, b_utxo) = add_budget(context, &builder, c, 3);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo, ora_utxo, b_utxo] })
}

/// An honest swap_in on the genuine PSM (family A) with a second, unrelated
/// kusd family B whose authority also runs `emission` gated on the same PSM.
fn build_swap_in_with_rider() -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let kusd_b_covid = Hash::from_bytes(FAKE_KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);

    let c: i64 = 400;
    let user = xonly(3);
    let gov = xonly(5);
    let attacker = xonly(9);
    let auth_in = kusd_state(1_000_000, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(1_000_000 - c, &gov, 0x10u8, &gate.ext);
    let emitted = kusd_state(c, &user, 0u8, &gate.ext);
    let b_auth_in = kusd_state(1_000_000, &gov, 0x10u8, &gate.ext);
    let b_auth_out = b_auth_in.clone();
    let b_stolen = kusd_state(1_000_000, &attacker, 0u8, &gate.ext);
    let ora = oracle_state(PRICE);
    let psm_in = psm_state(1_000, 0, KUSD_COVID, ORACLE_COVID);
    let psm_out = psm_state(1_000, c, KUSD_COVID, ORACLE_COVID);

    let kas_in = (kusd_v2_harness::sompi_of_ceil(c, PRICE)) as u64;
    let psm_value_in: u64 = TOMBSTONE + 2_000_000_000;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let b_auth_utxo = builder.covenant_utxo("kusd_app::Kusd", b_auth_in.clone(), DUST, 0, false, Some(kusd_b_covid)).expect("b auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let b_states = ArtifactValue::Array(vec![obj(b_auth_out.clone()), obj(b_stolen.clone())]);
    let user_arg = user.clone();

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Bytes(user_arg.clone())), ArgValue::Value(ArtifactValue::Int(4))]
            }),
            demo_outpoint(0x64, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0x65, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x66, 0), ora_utxo.clone(), 0)
        .actor_input(
            "kusd_app::Kusd",
            b_auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(b_states.clone(), 0, true)),
            demo_outpoint(0x67, 0),
            b_auth_utxo.clone(),
            0,
        )
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value_in + kas_in)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, oracle_covid), DUST)
        .actor_output("kusd_app::Kusd", b_auth_out, CovenantBinding::new(3, kusd_b_covid), DUST)
        .actor_output("kusd_app::Kusd", b_stolen, CovenantBinding::new(3, kusd_b_covid), DUST);
    let (context, b_utxo) = add_budget(context, &builder, c, 4);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo, ora_utxo, b_auth_utxo, b_utxo] })
}

/// swap_out of `c` cents: burner's holder box burns, redeemer gets c*1e8/price sompi.
fn build_swap_out(c: i64, ceiling: i64, minted: i64, holder_amount: i64, price: i64) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);

    let burner = xonly(7);
    let gov = xonly(5);
    let auth_amount: i64 = 999_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + c, &gov, 0x10u8, &gate.ext);
    let holder = kusd_state(holder_amount, &burner, 0u8, &gate.ext);
    let ora = oracle_state(price);
    let psm_in = psm_state(ceiling, minted, KUSD_COVID, ORACLE_COVID);
    let psm_out = psm_state(ceiling, minted - c, KUSD_COVID, ORACLE_COVID);

    let kas_out = if price > 0 { (kusd_v2_harness::sompi_of(c, price)) as u64 } else { 1 };
    let psm_value_in: u64 = TOMBSTONE + 2_000_000_000;
    let psm_value_out: u64 = psm_value_in - kas_out;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid)).expect("holder utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let burner_kp = demo_keypair(7);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let redeemer = burner.clone();

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_out").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner_kp))),
                    ArgValue::Value(ArtifactValue::Int(4)),
                ]
            }),
            demo_outpoint(0x71, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0x72, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(7))))]
            }),
            demo_outpoint(0x73, 0),
            holder_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x74, 0), ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), 2 * DUST)
        .output(p2pk_spk(&xonly(7)), None, kas_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(3, oracle_covid), DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r: c }, 4, BUDGET_COVID, KUSD_COVID, BUDGET_LIMIT, BUDGET_LIMIT - 1_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo, holder_utxo, ora_utxo, b_utxo] })
}

/// set_params under a frozen kusd family. signer key bytes pick the two signers.
fn build_set_params(new_ceiling: i64, new_spread: i64, idx: (i64, i64), keys: (u8, u8)) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);

    let gov = xonly(5);
    let auth = kusd_state(1_000_000, &gov, 0x10u8, &gate.ext);
    let psm_in = psm_state(1_000, 400, KUSD_COVID, ORACLE_COVID);
    let psm_out = psm_state_full(new_ceiling, 400, new_spread, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let psm_value: u64 = TOMBSTONE + 1_000_000_000;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");

    let k_a = demo_keypair(keys.0);
    let k_b = demo_keypair(keys.1);
    let emission_states = ArtifactValue::Array(vec![obj(auth.clone())]);

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("set_params").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(new_ceiling)),
                    ArgValue::Value(ArtifactValue::Int(new_spread)),
                    ArgValue::Value(ArtifactValue::Int(idx.0)),
                    ArgValue::Value(ArtifactValue::Int(idx.1)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &k_a))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &k_b))),
                ]
            }),
            demo_outpoint(0x81, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth.clone(),
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0x82, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value)
        .actor_output("kusd_app::Kusd", auth, CovenantBinding::new(1, kusd_covid), DUST);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo] })
}

fn build_wire(initial_kusd_id: [u8; 32], keys: (u8, u8)) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let psm_covid = Hash::from_bytes(PSM_COVID);

    let mut psm_in = psm_state_full(1_000, 0, 0, initial_kusd_id, ORACLE_COVID, ZERO32);
    psm_in.insert("budget_id".into(), ArtifactValue::Bytes(ZERO32.to_vec()));
    let psm_out = psm_state_full(1_000, 0, 0, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let psm_value: u64 = TOMBSTONE;
    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");

    let k_a = demo_keypair(keys.0);
    let k_b = demo_keypair(keys.1);
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("wire").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Bytes(KUSD_COVID.to_vec())),
                    ArgValue::Value(ArtifactValue::Bytes(SURPLUS_COVID.to_vec())),
                    ArgValue::Value(ArtifactValue::Bytes(BUDGET_COVID.to_vec())),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &k_a))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &k_b))),
                ]
            }),
            demo_outpoint(0xC1, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo] })
}

#[test]
fn wire_unwired_psm_ok() {
    let mut built = build_wire(ZERO32, (20, 22)).expect("wire builds");
    let report = meter(&mut built.tx, built.entries);
    println!("WIRE: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn wire_already_wired_rejected() {
    // one-time: a wired psm can never be re-pointed at another family
    let err = expect_rejected(build_wire([0x55; 32], (20, 22)), "input 0 script failed");
    println!("re-wire rejected: {err}");
}

#[test]
fn wire_bad_sig_rejected() {
    let err = expect_rejected(build_wire(ZERO32, (20, 33)), "input 0 script failed");
    println!("wire bad sig rejected: {err}");
}

#[test]
fn swap_in_ok_and_metered() {
    let mut built = build_swap_in(400, 1_000, 0, KUSD_COVID, 0x07, 0x66).expect("swap_in builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SWAP_IN: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn swap_in_over_ceiling_rejected() {
    let err = expect_rejected(build_swap_in(601, 1_000, 400, KUSD_COVID, 0x07, 0x66), "script ran, but verification failed");
    println!("over ceiling rejected: {err}");
}

#[test]
fn swap_out_ok_and_metered() {
    let mut built = build_swap_out(400, 1_000, 500, 400, PRICE).expect("swap_out builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SWAP_OUT: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn swap_out_never_ceiling_blocked() {
    // Review Focus 2 / SPEC §3: governance shrank the ceiling below the
    // outstanding minted amount — redemption must still work
    let mut built = build_swap_out(400, 100, 500, 400, PRICE).expect("swap_out builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn swap_out_beyond_minted_rejected() {
    let err = expect_rejected(build_swap_out(400, 1_000, 300, 400, PRICE), "script ran, but verification failed");
    println!("beyond minted rejected: {err}");
}

#[test]
fn swap_out_burn_short_rejected() {
    let err = expect_rejected(build_swap_out(400, 1_000, 500, 300, PRICE), "script ran, but verification failed");
    println!("burn short rejected: {err}");
}

#[test]
fn set_params_2of3_ok() {
    let mut built = build_set_params(2_000, 0, (0, 2), (20, 22)).expect("set_ceiling builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SET_CEILING: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn set_params_below_minted_ok() {
    // the ceiling may stop growth below the outstanding amount; it never unwinds
    let mut built = build_set_params(100, 0, (0, 2), (20, 22)).expect("set_ceiling builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn set_ceiling_bad_sig_rejected() {
    let err = expect_rejected(build_set_params(2_000, 0, (0, 1), (20, 33)), "script ran, but verification failed");
    println!("bad gov sig rejected: {err}");
}

#[test]
fn hostile_psm_instance_rejected() {
    // review C-1: a permissionlessly genesis'd PSM from the genuine template,
    // correctly wired but with its own huge ceiling and governance keys, must
    // NOT satisfy the emission gate — the config pins the INSTANCE (covid),
    // so the governance ceiling is real, not decorative
    let err = expect_rejected(
        build_swap_in(400, i64::MAX / 2, 0, KUSD_COVID, 0x07, 0x67),
        "input 1 script failed",
    );
    println!("hostile psm instance rejected: {err}");
}

#[test]
fn psm_emission_unrelated_family_rider_rejected() {
    // review I-3: the genuine PSM gating family A cannot cover an emission of
    // family B riding the same tx (pgate.kusd_id == self.cov_id on B fails)
    let err = expect_rejected(build_swap_in_with_rider(), "input 3 script failed");
    println!("psm rider rejected: {err}");
}

#[test]
fn swap_out_zero_price_rejected() {
    // review I-1 (plan Task 4): the PSM's explicit price bound, not a division
    // abort, must refuse a zero-price feed
    let err = expect_rejected(build_swap_out(400, 1_000, 500, 400, 0), "script failed");
    println!("psm zero price rejected: {err}");
}

#[test]
fn psm_emission_wrong_group_rejected() {
    // C1 analog: a PSM wired to another kusd family cannot gate THIS family's
    // emission (the hostile swap_in observes its own family, which is absent,
    // so group resolution or the gate check must refuse)
    let err = expect_rejected(build_swap_in(400, 1_000, 0, FAKE_KUSD_COVID, 0x07, 0x66), "expects");
    println!("wrong-group psm rejected: {err}");
}

#[test]
fn psm_emission_wrong_oracle_rejected() {
    // C2 analog: a PSM wired to a non-anchored oracle must fail the gate
    let err = expect_rejected(build_swap_in(400, 1_000, 0, KUSD_COVID, 0x08, 0x66), "script ran, but verification failed");
    println!("wrong-oracle psm rejected: {err}");
}

// --- Phase 4: fee switch -------------------------------------------------------

#[test]
fn set_params_spread_above_cap_rejected() {
    let err = expect_rejected(build_set_params(2_000, 201, (0, 2), (20, 22)), "script ran, but verification failed");
    println!("spread above cap rejected: {err}");
}

/// swap_in_fee: c cents at `price` with `spread` bps routed to the surplus box.
/// `surplus_covid_byte` != 0x77 simulates a hostile surplus instance;
/// `fee_paid_delta` underpays/overpays the surplus continuation.
fn build_swap_in_fee(c: i64, price: i64, spread: i64, surplus_covid_byte: u8, fee_paid_delta: i64) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);
    let surplus_covid = Hash::from_bytes([surplus_covid_byte; 32]);

    let user = xonly(3);
    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount - c, &gov, 0x10u8, &gate.ext);
    let emitted = kusd_state(c, &user, 0u8, &gate.ext);
    let ora = oracle_state(price);
    let psm_in = psm_state_full(100_000, 0, spread, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let psm_out = psm_state_full(100_000, c, spread, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let s_in = surplus_state();

    let kas_in = kusd_v2_harness::sompi_of_ceil(c, price);
    let fee = kas_in * spread / 10_000;
    let psm_value_in: u64 = TOMBSTONE;
    let psm_value_out: u64 = (TOMBSTONE as i64 + kas_in) as u64;
    let s_value_in: u64 = TOMBSTONE;
    let s_value_out: u64 = (TOMBSTONE as i64 + fee + fee_paid_delta) as u64;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), s_value_in, 0, false, Some(surplus_covid)).expect("surplus utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let recipient = user.clone();
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in_fee").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Bytes(recipient.clone())), ArgValue::Value(ArtifactValue::Int(4))]
            }),
            demo_outpoint(0xD1, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0xD2, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", demo_outpoint(0xD3, 0), s_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xD4, 0), ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("surplus_app::Surplus", s_in, CovenantBinding::new(2, surplus_covid), s_value_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(3, oracle_covid), DUST);
    let (context, b_utxo) = add_budget(context, &builder, c, 4);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo, s_utxo, ora_utxo, b_utxo] })
}

/// swap_out_fee: redemption with the spread out of the payout.
fn build_swap_out_fee(c: i64, price: i64, spread: i64, payout_delta: i64) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);
    let surplus_covid = Hash::from_bytes(SURPLUS_COVID);

    let burner = xonly(7);
    let gov = xonly(5);
    let auth_amount: i64 = 999_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + c, &gov, 0x10u8, &gate.ext);
    let holder = kusd_state(c, &burner, 0u8, &gate.ext);
    let ora = oracle_state(price);
    let psm_in = psm_state_full(100_000, c, spread, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let psm_out = psm_state_full(100_000, 0, spread, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let s_in = surplus_state();

    let kas_out = kusd_v2_harness::sompi_of(c, price);
    let fee = kas_out * spread / 10_000;
    let psm_value_in: u64 = TOMBSTONE + 2_000_000_000;
    let psm_value_out: u64 = (psm_value_in as i64 - kas_out) as u64;
    let s_value_out: u64 = (TOMBSTONE as i64 + fee) as u64;

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid)).expect("holder utxo");
    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), TOMBSTONE, 0, false, Some(surplus_covid)).expect("surplus utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let burner_kp = demo_keypair(7);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let redeemer = burner.clone();
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_out_fee").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner_kp))),
                    ArgValue::Value(ArtifactValue::Int(5)),
                ]
            }),
            demo_outpoint(0xD5, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0xD6, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(7))))]
            }),
            demo_outpoint(0xD7, 0),
            holder_utxo.clone(),
            0,
        )
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", demo_outpoint(0xD8, 0), s_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xD9, 0), ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), 2 * DUST)
        .output(p2pk_spk(&xonly(7)), None, (kas_out - fee + payout_delta) as u64)
        .actor_output("surplus_app::Surplus", s_in, CovenantBinding::new(3, surplus_covid), s_value_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(4, oracle_covid), DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r: c }, 5, BUDGET_COVID, KUSD_COVID, BUDGET_LIMIT, BUDGET_LIMIT - 1_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![psm_utxo, auth_utxo, holder_utxo, s_utxo, ora_utxo, b_utxo] })
}

#[test]
fn swap_in_fee_routes_spread_to_surplus_and_metered() {
    // 400c at 40c/KAS = 1e9 sompi in; 25 bps -> 2.5M sompi to surplus
    let mut built = build_swap_in_fee(400, PRICE, 25, 0x77, 0).expect("swap_in_fee builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SWAP_IN_FEE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn swap_out_fee_routes_spread_and_metered() {
    let mut built = build_swap_out_fee(400, PRICE, 25, 0).expect("swap_out_fee builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SWAP_OUT_FEE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn swap_fee_minimal_swap_still_pays_fee() {
    // with reserve inflows rounded UP (review M-2), the smallest swap — 1 cent at
    // $10,000/KAS — pays 1e-4 KAS into the reserve and a nonzero fee (25 sompi):
    // dust swaps can't evade the spread; the contract's `fee > 0` guard is now
    // defense in depth
    let kas_in = kusd_v2_harness::sompi_of_ceil(1, 100_000_000);
    assert_eq!((kas_in, kas_in * 25 / 10_000), (10_000, 25));
    let mut built = build_swap_in_fee(1, 100_000_000, 25, 0x77, 0).expect("minimal fee swap builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn swap_fee_hostile_surplus_rejected() {
    // genuine surplus template, wrong covid: the observe-by-covid pin must refuse it
    let err = expect_rejected(build_swap_in_fee(400, PRICE, 25, 0x78, 0), "");
    println!("hostile surplus rejected: {err}");
}

#[test]
fn swap_fee_surplus_underpaid_rejected() {
    let err = expect_rejected(build_swap_in_fee(400, PRICE, 25, 0x77, -2_500_000), "script ran, but verification failed");
    println!("underpaid surplus rejected: {err}");
}

#[test]
fn swap_out_fee_payout_overdraw_rejected() {
    // redeemer tries to take the gross kas_out despite the fee
    let err = expect_rejected(build_swap_out_fee(400, PRICE, 25, 2_500_000), "script ran, but verification failed");
    println!("payout overdraw rejected: {err}");
}

#[test]
fn swap_plain_with_nonzero_spread_rejected() {
    // the no-surplus fast path must refuse to run while the fee switch is on:
    // a swap_in against a psm whose state carries spread 25
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let psm_covid = Hash::from_bytes(PSM_COVID);
    let (user, gov) = (xonly(3), xonly(5));
    let c: i64 = 400;
    let auth_in = kusd_state(1_000_000, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(1_000_000 - c, &gov, 0x10u8, &gate.ext);
    let emitted = kusd_state(c, &user, 0u8, &gate.ext);
    let ora = oracle_state(PRICE);
    let psm_in = psm_state_full(100_000, 0, 25, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let psm_out = psm_state_full(100_000, c, 25, KUSD_COVID, ORACLE_COVID, SURPLUS_COVID);
    let kas_in = kusd_v2_harness::sompi_of_ceil(c, PRICE);
    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), TOMBSTONE, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let recipient = user.clone();
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Bytes(recipient.clone())), ArgValue::Value(ArtifactValue::Int(3))]
            }),
            demo_outpoint(0xDA, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            demo_outpoint(0xDB, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xDC, 0), ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(0, psm_covid), (TOMBSTONE as i64 + kas_in) as u64)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, oracle_covid), DUST);
    let (context, b_utxo) = add_budget(context, &builder, c, 3);
    let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries: vec![psm_utxo, auth_utxo, ora_utxo, b_utxo] });
    let err = expect_rejected(result, "script ran, but verification failed");
    println!("plain swap with fee switch on rejected: {err}");
}


// --- Phase 5: oracle status — swap_in needs LIVE; the peg floor never stops --------

#[test]
fn swap_in_on_frozen_oracle_rejected() {
    let err = expect_rejected(with_status(1, || build_swap_in(400, 1_000, 0, KUSD_COVID, 0x07, 0x66)), "script ran, but verification failed");
    println!("swap_in on frozen feed rejected: {err}");
}

#[test]
fn swap_out_on_frozen_oracle_ok() {
    let mut built = with_status(1, || build_swap_out(400, 1_000, 500, 400, PRICE)).expect("redemption on a frozen feed builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn swap_out_on_settled_oracle_ok() {
    let mut built = with_status(2, || build_swap_out(400, 1_000, 500, 400, PRICE)).expect("redemption on a settled feed builds");
    meter(&mut built.tx, built.entries);
}
