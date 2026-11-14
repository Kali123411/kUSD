// Phase 2 Task 3: vault collateral adjust (frozen kusd family) + authority
// key rotation.
// adjust tx: [vault, authority(frozen), oracle] -> [vault', auth'(=auth), oracle']
// rotate tx: [authority] -> [authority'(new owner)]

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{build_app, demo_keypair, demo_outpoint, gate_setup, meter, meter_expect_err, protocol_runtime, sign_input};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const TOMBSTONE: u64 = 100_000_000;
const KUSD_COVID: [u8; 32] = [0x42; 32];
const ORACLE_COVID: [u8; 32] = [0x07; 32];
const PSM_COVID: [u8; 32] = [0x66; 32];
const VAULT_COVID: [u8; 32] = [0x99; 32];
const ZERO32: [u8; 32] = [0u8; 32];
const SURPLUS_COVID: [u8; 32] = [0x77; 32];
const BUDGET_COVID: [u8; 32] = [0x88; 32];

const COLLATERAL: i64 = 1_000_000_000; // 10 KAS
const DEBT: i64 = 200;
const PRICE: i64 = 4_000; // 1e-4 USD/KAS: $0.40

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

fn oracle_state(price: i64) -> BTreeMap<String, ArtifactValue> {
    kusd_v2_harness::oracle_state_v2(price)
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

fn build_adjust(delta: i64, price: i64, auth_out_delta: i64) -> Result<Built, String> {
    build_adjust_status(delta, price, auth_out_delta, 0)
}

fn build_adjust_status(delta: i64, price: i64, auth_out_delta: i64, status: i64) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes(ORACLE_COVID);
    let vault_covid = Hash::from_bytes(VAULT_COVID);

    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + auth_out_delta, &gov, 0x10u8, &gate.ext);
    let ora = kusd_v2_harness::oracle_state_full(price, price, price, 0, status);
    let vault_in = vault_state(COLLATERAL, DEBT);
    let vault_out = vault_state(COLLATERAL + delta, DEBT);

    let vault_value_in: u64 = TOMBSTONE + COLLATERAL as u64 + 700_000_000; // surplus covers deposits
    let vault_value_out: u64 = TOMBSTONE + (COLLATERAL + delta) as u64;

    let vault_utxo = builder
        .covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value_in, 0, false, Some(vault_covid))
        .expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let owner_kp = demo_keypair(1);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let (vplen, vslen) = (gate.vault_prefix_len, gate.vault_suffix_len);
    let cfg = (gate.vault_template.clone(), gate.psm_template.clone(), gate.oracle_covid.clone(), gate.psm_covid.clone(), gate.surplus_covid.clone(), gate.budget_covid.clone());

    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("adjust").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(delta)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                ]
            }),
            demo_outpoint(0x91, 0),
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| {
                vec![
                    ArgValue::Value(emission_states.clone()),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(vplen)),
                    ArgValue::Value(ArtifactValue::Int(vslen)),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.0.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.1.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.2.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.3.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.4.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.5.clone())),
                    ArgValue::Value(ArtifactValue::Bool(false)),
                ]
            }),
            demo_outpoint(0x92, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x93, 0), ora_utxo.clone(), 0)
        .actor_output("vault_app::Vault", vault_out, CovenantBinding::new(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, oracle_covid), DUST);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![vault_utxo, auth_utxo, ora_utxo] })
}

fn build_rotate(scheme: u8, signer_key: u8) -> Result<Built, String> {
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let kusd_covid = Hash::from_bytes(KUSD_COVID);

    let old_owner = xonly(5);
    let new_owner = xonly(6);
    let box_in = kusd_state(1_000_000, &old_owner, scheme, &gate.ext);
    let box_out = kusd_state(1_000_000, &new_owner, scheme, &gate.ext);
    let utxo = builder.covenant_utxo("Kusd", box_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");

    let signer = demo_keypair(signer_key);
    let new_owner_arg = new_owner.clone();
    let context = TxContext::new()
        .actor_input(
            "Kusd",
            box_in,
            EntryCall::new("rotate").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Bytes(new_owner_arg.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer))),
                ]
            }),
            demo_outpoint(0xA1, 0),
            utxo.clone(),
            0,
        )
        .actor_output("Kusd", box_out, CovenantBinding::new(0, kusd_covid), DUST);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

#[test]
fn adjust_deposit_ok() {
    let mut built = build_adjust(500_000_000, PRICE, 0).expect("deposit builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn adjust_withdraw_healthy_ok_and_metered() {
    // 9 KAS at 40c = $3.60 -> 360*100 >= 200*175 = 35000: still healthy
    let mut built = build_adjust(-100_000_000, PRICE, 0).expect("withdraw builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ADJUST: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn adjust_withdraw_unhealthy_rejected() {
    // 8 KAS -> 320*100 < 35000
    let err = expect_rejected(build_adjust(-200_000_000, PRICE, 0), "script ran, but verification failed");
    println!("unhealthy withdraw rejected: {err}");
}

#[test]
fn adjust_cannot_move_supply_rejected() {
    // Review Focus 1: supply is frozen under adjust — an emission riding this
    // vault entry cannot change the authority amount
    let err = expect_rejected(build_adjust(-100_000_000, PRICE, -1), "script ran, but verification failed");
    println!("supply move under adjust rejected: {err}");
}

#[test]
fn rotate_authority_ok() {
    let mut built = build_rotate(0x10, 5).expect("rotate builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ROTATE: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn rotate_non_authority_rejected() {
    let err = expect_rejected(build_rotate(0x00, 5), "script ran, but verification failed");
    println!("non-authority rotate rejected: {err}");
}

#[test]
fn rotate_wrong_sig_rejected() {
    let err = expect_rejected(build_rotate(0x10, 9), "script ran, but verification failed");
    println!("wrong-sig rotate rejected: {err}");
}


// --- Phase 5: withdrawals need a LIVE feed; deposits always work ---------------------

#[test]
fn withdraw_on_frozen_oracle_rejected() {
    let err = expect_rejected(build_adjust_status(-100_000_000, PRICE, 0, 1), "script ran, but verification failed");
    println!("withdraw on frozen feed rejected: {err}");
}

#[test]
fn deposit_on_frozen_oracle_ok() {
    let mut built = build_adjust_status(500_000_000, PRICE, 0, 1).expect("deposit on a frozen feed builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn deposit_while_unhealthy_ok() {
    // at $0.15 the vault (10 KAS, 200c debt) is underwater; a partial top-up of
    // 1 KAS doesn't restore health but must still be accepted
    let mut built = build_adjust(100_000_000, 1_500, 0).expect("partial top-up of an unhealthy vault builds");
    meter(&mut built.tx, built.entries);
}
