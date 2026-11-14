// Phase 4 Task 4: governance surplus covenant — box value IS the balance;
// permissionless `receive` (value never decreases), 2-of-3 `spend` with the
// payout pinned at tx.outputs[1].

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{build_app, demo_keypair, demo_outpoint, meter, meter_expect_err, sign_input};
use std::collections::BTreeMap;

const TOMBSTONE: u64 = 100_000_000;
const SURPLUS_COVID: [u8; 32] = [0x55; 32];
const KUSD_COVID: [u8; 32] = [0x42; 32];

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

fn surplus_state() -> BTreeMap<String, ArtifactValue> {
    state! { g0: xonly(20), g1: xonly(21), g2: xonly(22), kusd_id: KUSD_COVID.to_vec() }
}

fn tampered_state() -> BTreeMap<String, ArtifactValue> {
    state! { g0: xonly(29), g1: xonly(21), g2: xonly(22), kusd_id: KUSD_COVID.to_vec() }
}

struct Built {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<kaspa_consensus_core::tx::UtxoEntry>,
}

fn expect_rejected(result: Result<Built, String>, expect: &str) -> String {
    let err = match result {
        Err(build_err) => build_err,
        Ok(mut built) => meter_expect_err(&mut built.tx, built.entries),
    };
    assert!(err.contains(expect), "rejected for the wrong reason: wanted '{expect}' in '{err}'");
    err
}

fn p2pk_spk(owner: &[u8]) -> kaspa_consensus_core::tx::ScriptPublicKey {
    let mut spk = vec![0x20];
    spk.extend_from_slice(owner);
    spk.push(0xac);
    kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, spk)
}

fn build_receive(value_in: u64, value_out: u64, out_state: BTreeMap<String, ArtifactValue>) -> Result<Built, String> {
    let artifact = build_app("surplus", "../ag/surplus.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(SURPLUS_COVID);
    let st = surplus_state();
    let utxo = builder.covenant_utxo("Surplus", st.clone(), value_in, 0, false, Some(covid)).expect("surplus utxo");
    // a plain funding input covers the top-up + fee (OP_TRUE utxo, test-only)
    let funding = kaspa_consensus_core::tx::UtxoEntry::new(
        1_000_000_000,
        kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, vec![0x51]),
        0,
        false,
        None,
    );
    let context = TxContext::new()
        .actor_input("Surplus", st, "receive", demo_outpoint(0x81, 0), utxo.clone(), 0)
        .input(demo_outpoint(0x82, 0), funding.clone(), Vec::new(), 0)
        .actor_output("Surplus", out_state, CovenantBinding::new(0, covid), value_out);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo, funding] })
}

fn build_spend(amount: i64, value_out: u64, idx: (i64, i64), keys: (u8, u8), dest_tamper: bool) -> Result<Built, String> {
    let artifact = build_app("surplus", "../ag/surplus.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(SURPLUS_COVID);
    let st = surplus_state();
    let value_in: u64 = 1_000_000_000; // 10 KAS of accumulated fees
    let utxo = builder.covenant_utxo("Surplus", st.clone(), value_in, 0, false, Some(covid)).expect("surplus utxo");

    let dest = p2pk_spk(&xonly(if dest_tamper { 8 } else { 7 }));
    let (ka, kb) = (demo_keypair(keys.0), demo_keypair(keys.1));
    let dest_bytes = xonly(7);
    let context = TxContext::new()
        .actor_input(
            "Surplus",
            st.clone(),
            EntryCall::new("spend").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(amount)),
                    ArgValue::Value(ArtifactValue::Bytes(dest_bytes.clone())),
                    ArgValue::Value(ArtifactValue::Int(idx.0)),
                    ArgValue::Value(ArtifactValue::Int(idx.1)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ka))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kb))),
                ]
            }),
            demo_outpoint(0x83, 0),
            utxo.clone(),
            0,
        )
        .actor_output("Surplus", st, CovenantBinding::new(0, covid), value_out)
        .output(dest, None, amount as u64);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

#[test]
fn receive_topup_ok_and_metered() {
    let mut built = build_receive(TOMBSTONE, TOMBSTONE + 500_000_000, surplus_state()).expect("top-up builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SURPLUS RECEIVE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn receive_value_decrease_rejected() {
    let err = expect_rejected(build_receive(TOMBSTONE + 500_000_000, TOMBSTONE, surplus_state()), "script ran, but verification failed");
    println!("receive drain rejected: {err}");
}

#[test]
fn receive_state_tamper_rejected() {
    let err = expect_rejected(build_receive(TOMBSTONE, TOMBSTONE + 500_000_000, tampered_state()), "");
    println!("receive gov-key tamper rejected: {err}");
}

#[test]
fn spend_2of3_ok_and_metered() {
    let mut built = build_spend(400_000_000, 600_000_000, (0, 2), (20, 22), false).expect("spend builds");
    let report = meter(&mut built.tx, built.entries);
    println!("SURPLUS SPEND: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn spend_wrong_key_rejected() {
    let err = expect_rejected(build_spend(400_000_000, 600_000_000, (0, 2), (20, 29), false), "script ran, but verification failed");
    println!("spend wrong key rejected: {err}");
}

#[test]
fn spend_same_index_rejected() {
    let err = expect_rejected(build_spend(400_000_000, 600_000_000, (1, 1), (21, 21), false), "script ran, but verification failed");
    println!("spend same-index rejected: {err}");
}

#[test]
fn spend_below_tombstone_rejected() {
    let err = expect_rejected(build_spend(950_000_000, 50_000_000, (0, 1), (20, 21), false), "script ran, but verification failed");
    println!("spend below tombstone rejected: {err}");
}

#[test]
fn spend_dest_tamper_rejected() {
    // governance signed dest A, outputs[1] pays dest B
    let err = expect_rejected(build_spend(400_000_000, 600_000_000, (0, 1), (20, 21), true), "script ran, but verification failed");
    println!("spend dest tamper rejected: {err}");
}

#[test]
fn spend_amount_mismatch_rejected() {
    // continuation keeps 700M but claims amount 400M (outputs[1] value check)
    let err = expect_rejected(build_spend(400_000_000, 700_000_000, (0, 1), (20, 21), false), "script ran, but verification failed");
    println!("spend amount mismatch rejected: {err}");
}
