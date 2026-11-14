// Phase 4 Task 6: vault lineage termination — `close` (emits none) releases a
// debt-free vault's value to its owner, under the frozen kusd family (an
// emission must not be able to ride a close; kusd.ag INVARIANT).
// tx: [vault(close), authority(emission, frozen)] -> [auth', release(P2PK owner)]

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{demo_keypair, demo_outpoint, gate_setup, meter, meter_expect_err, protocol_runtime, sign_input};
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

const COLLATERAL: i64 = 1_000_000_000;

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

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
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

fn build_close(debt: i64, signer_key: u8, auth_out_delta: i64, with_vault_continuation: bool) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let vault_covid = Hash::from_bytes(VAULT_COVID);

    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + auth_out_delta, &gov, 0x10u8, &gate.ext);
    let v_in = vault_state(COLLATERAL, debt);
    let vault_value: u64 = TOMBSTONE + COLLATERAL as u64;

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", v_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid)).expect("auth utxo");

    let signer = demo_keypair(signer_key);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let mut context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            v_in.clone(),
            EntryCall::new("close").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer)))]
            }),
            demo_outpoint(0xE1, 0),
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| {
                let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
                vec![
                    ArgValue::Value(emission_states.clone()),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(gate.vault_prefix_len)),
                    ArgValue::Value(ArtifactValue::Int(gate.vault_suffix_len)),
                    ArgValue::Value(ArtifactValue::Bytes(gate.vault_template.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(gate.psm_template.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(gate.oracle_covid.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(gate.psm_covid.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(gate.surplus_covid.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(gate.budget_covid.clone())),
                    ArgValue::Value(ArtifactValue::Bool(false)),
                ]
            }),
            demo_outpoint(0xE2, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .output(p2pk_spk(&xonly(1)), None, vault_value - 5_000_000); // release minus fee
    if with_vault_continuation {
        context = context.actor_output("vault_app::Vault", vault_state(COLLATERAL, 0), CovenantBinding::new(0, vault_covid), vault_value);
    }
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![vault_utxo, auth_utxo] })
}

#[test]
fn close_debt_zero_releases_ok_and_metered() {
    let mut built = build_close(0, 1, 0, false).expect("close builds");
    let report = meter(&mut built.tx, built.entries);
    println!("CLOSE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn close_with_debt_rejected() {
    let err = expect_rejected(build_close(200, 1, 0, false), "script ran, but verification failed");
    println!("close with debt rejected: {err}");
}

#[test]
fn close_wrong_sig_rejected() {
    let err = expect_rejected(build_close(0, 9, 0, false), "script ran, but verification failed");
    println!("close wrong sig rejected: {err}");
}

#[test]
fn close_supply_move_rejected() {
    // an emission riding the close cannot change the authority amount (frozen family)
    let err = expect_rejected(build_close(0, 1, -1, false), "script ran, but verification failed");
    println!("supply move under close rejected: {err}");
}

#[test]
fn close_cannot_emit_vault_continuation() {
    // `emits none`: the closed lineage must not continue in the same tx
    let err = expect_rejected(build_close(0, 1, 0, true), "");
    println!("vault continuation after close rejected: {err}");
}
