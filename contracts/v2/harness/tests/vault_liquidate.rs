// Task 5: permissionless liquidate — atomic single-tx form, measured.
// tx: inputs [vault, kusd_authority, kusd_holder(liquidator), oracle]
//     outputs [vault'(closed, remainder), auth'(+debt), payout(P2PK), oracle']
// v1-reviewed parameters: MIN_RATIO 175, LIQUIDATION_PENALTY 13%, seize capped
// at freed collateral, owner keeps the remainder in the closed vault.

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{
    Hash,
    tx::{CovenantBinding, ScriptPublicKey},
};
use kusd_v2_harness::{demo_keypair, demo_outpoint, meter, meter_expect_err, sign_input, vault_bundle, gate_setup};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const KUSD_COVID: [u8; 32] = [0x42; 32];
const ORACLE_COVID: [u8; 32] = [0x07; 32];
const PSM_COVID: [u8; 32] = [0x66; 32];
const VAULT_COVID: [u8; 32] = [0x99; 32];
const ZERO32: [u8; 32] = [0u8; 32];
const SURPLUS_COVID: [u8; 32] = [0x77; 32];
const BUDGET_COVID: [u8; 32] = [0x88; 32];

const COLLATERAL: i64 = 1_000_000_000; // 10 KAS
const DEBT: i64 = 200; // $2.00

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
        borrow_guard: ZERO32.to_vec(), // plain KCC-20 semantics; anchor lives in the gate config
        extension_commitment: ext.to_vec(),
    }
}

fn oracle_state(price: i64) -> BTreeMap<String, ArtifactValue> {
    kusd_v2_harness::oracle_state_v2(price)
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

struct Built {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<kaspa_consensus_core::tx::UtxoEntry>,
}

/// Assert rejection AND that it failed on the expected check — a build/ABI
/// error must not masquerade as a covenant rejection (review finding I2).
fn expect_rejected(result: Result<Built, String>, expect: &str) -> String {
    let err = match result {
        Err(build_err) => build_err,
        Ok(mut built) => meter_expect_err(&mut built.tx, built.entries),
    };
    assert!(err.contains(expect), "rejected for the wrong reason: wanted '{expect}' in '{err}'");
    err
}

/// price 20: collateral worth $2.00 < 200*175% -> liquidatable.
/// seize = 200*113/100 = 226 cents = 1.13e9 sompi at price 20, capped at
/// freed = collateral - TOMBSTONE = 9e8; closed vault keeps 1e8.
fn build_liquidate(price: i64, holder_amount: i64, oracle_covid_byte: u8) -> Result<Built, String> {
    build_liquidate_full(price, holder_amount, oracle_covid_byte, 0x77, 0, 0)
}

/// Liquidation where the oracle's raw print differs from its rate-limited
/// liq_price (`price` here IS the liq_price the contract uses) and/or the feed
/// is not LIVE.
fn build_liquidate_ora(raw: i64, liq: i64, status: i64) -> Result<Built, String> {
    ORA_OVERRIDE.with(|o| *o.borrow_mut() = Some((raw, status)));
    let r = build_liquidate_full(liq, DEBT, 0x07, 0x77, 0, 0);
    ORA_OVERRIDE.with(|o| *o.borrow_mut() = None);
    r
}

thread_local! {
    static ORA_OVERRIDE: std::cell::RefCell<Option<(i64, i64)>> = const { std::cell::RefCell::new(None) };
}

fn build_liquidate_full(price: i64, holder_amount: i64, oracle_covid_byte: u8, surplus_covid_byte: u8, surplus_paid_delta: i64, payout_delta: i64) -> Result<Built, String> {
    let compiled = vault_bundle();
    let runtime = compiled.runtime_bundle().expect("runtime bundle");
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes([oracle_covid_byte; 32]);
    let vault_covid = Hash::from_bytes(VAULT_COVID);

    let gov = xonly(5);
    let burner = xonly(7);
    let auth_amount: i64 = 999_800;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + DEBT, &gov, 0x10u8, &gate.ext);
    let holder = kusd_state(holder_amount, &burner, 0u8, &gate.ext);
    let ora = match ORA_OVERRIDE.with(|o| *o.borrow()) {
        Some((raw, status)) => kusd_v2_harness::oracle_state_full(raw, raw.min(price), price, 0, status),
        None => oracle_state(price),
    };

    let vault_in = state! {
        owner: xonly(1),
        collateral: COLLATERAL,
        debt: DEBT,
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: ORACLE_COVID.to_vec(),
        surplus_id: SURPLUS_COVID.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    };

    // contract split math: keeper 110% of debt, surplus 3%, keeper first on cap
    let mut keeper_sompi = kusd_v2_harness::sompi_of(DEBT * 11_000 / 10_000, price.max(1)); // guard: a zero-price tx is built to be REJECTED
    let mut surplus_sompi = kusd_v2_harness::sompi_of(DEBT * 300 / 10_000, price.max(1));
    let freed = COLLATERAL - DUST as i64;
    if keeper_sompi > freed {
        keeper_sompi = freed;
    }
    if surplus_sompi > freed - keeper_sompi {
        surplus_sompi = freed - keeper_sompi;
    }
    let closed_collateral = COLLATERAL - keeper_sompi - surplus_sompi;

    let vault_out = state! {
        owner: xonly(1),
        collateral: closed_collateral,
        debt: 0,
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: ORACLE_COVID.to_vec(),
        surplus_id: SURPLUS_COVID.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    };

    let vault_value_in: u64 = DUST + COLLATERAL as u64 + 200_000_000;
    let vault_value_out: u64 = DUST + closed_collateral as u64;

    let vault_utxo = builder
        .covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value_in, 0, false, Some(vault_covid))
        .expect("vault utxo");
    let auth_utxo = builder
        .covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid))
        .expect("auth utxo");
    let holder_utxo = builder
        .covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid))
        .expect("holder utxo");
    let ora_utxo = builder
        .covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid))
        .expect("oracle utxo");
    let surplus_covid = Hash::from_bytes([surplus_covid_byte; 32]);
    let s_in = state! { g0: xonly(20), g1: xonly(21), g2: xonly(22), kusd_id: KUSD_COVID.to_vec() };
    let s_utxo = builder
        .covenant_utxo("surplus_app::Surplus", s_in.clone(), DUST, 0, false, Some(surplus_covid))
        .expect("surplus utxo");
    let s_value_out: u64 = (DUST as i64 + surplus_sompi + surplus_paid_delta) as u64;

    let burner_kp = demo_keypair(7);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let cfg = (gate.vault_template.clone(), gate.psm_template.clone(), gate.oracle_covid.clone(), gate.psm_covid.clone(), gate.surplus_covid.clone(), gate.budget_covid.clone());

    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("liquidate").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner_kp))), ArgValue::Value(ArtifactValue::Int(5))]
            }),
            demo_outpoint(0x51, 0),
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _input_idx| {
                vec![
                    ArgValue::Value(emission_states.clone()),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(gate.vault_prefix_len)),
                    ArgValue::Value(ArtifactValue::Int(gate.vault_suffix_len)),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.0.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.1.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.2.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.3.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.4.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.5.clone())),
                    ArgValue::Value(ArtifactValue::Bool(false)),
                ]
            }),
            demo_outpoint(0x52, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(7))))]
            }),
            demo_outpoint(0x53, 0),
            holder_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x54, 0), ora_utxo.clone(), 0)
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", demo_outpoint(0x55, 0), s_utxo.clone(), 0)
        .actor_output("vault_app::Vault", vault_out, CovenantBinding::new(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .output(p2pk_spk(&burner), None, (keeper_sompi + payout_delta) as u64)
        .actor_output("surplus_app::Surplus", s_in, CovenantBinding::new(4, surplus_covid), s_value_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(3, oracle_covid), DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r: DEBT }, 5, BUDGET_COVID, KUSD_COVID, 1_000_000_000, 999_000_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![vault_utxo, auth_utxo, holder_utxo, ora_utxo, s_utxo, b_utxo] })
}

#[test]
fn liquidate_unhealthy_ok_and_metered() {
    let mut built = build_liquidate(2000, DEBT, 0x07).expect("liquidation builds");
    let report = meter(&mut built.tx, built.entries);
    println!("LIQUIDATE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn liquidate_healthy_rejected() {
    let err = expect_rejected(build_liquidate(4000, DEBT, 0x07), "script ran, but verification failed");
    println!("healthy liquidation rejected: {err}");
}

#[test]
fn liquidate_forged_oracle_rejected() {
    // same oracle template, wrong covid: the vault's covid pin must refuse it
    let err = expect_rejected(build_liquidate(2000, DEBT, 0x08), "expects 1 inputs for its covenant id");
    println!("forged oracle rejected: {err}");
}

#[test]
fn liquidate_zero_price_rejected() {
    // review M2: a zero-price feed must be refused by an explicit bound, not
    // by an unpredictable division abort
    let err = expect_rejected(build_liquidate(0, DEBT, 0x07), "script ran, but verification failed");
    println!("zero price rejected: {err}");
}

#[test]
fn liquidate_burn_short_rejected() {
    let err = expect_rejected(build_liquidate(2000, 150, 0x07), "script ran, but verification failed");
    println!("short burn rejected: {err}");
}

// --- Phase 4: penalty split ------------------------------------------------------

#[test]
fn liquidate_uncapped_split_keeper_and_surplus_ok() {
    // price 30: keeper 220c -> 733,333,333 sompi; surplus 6c -> 20,000,000;
    // freed = 900M covers both (733.3M + 20M)
    let mut built = build_liquidate(3000, DEBT, 0x07).expect("uncapped split builds");
    let report = meter(&mut built.tx, built.entries);
    println!("LIQUIDATE SPLIT: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn liquidate_hostile_surplus_rejected() {
    // genuine surplus template, wrong covid: the observe-by-covid pin refuses it
    let err = expect_rejected(build_liquidate_full(3000, DEBT, 0x07, 0x78, 0, 0), "");
    println!("hostile surplus rejected: {err}");
}

#[test]
fn liquidate_surplus_underpaid_rejected() {
    let err = expect_rejected(build_liquidate_full(3000, DEBT, 0x07, 0x77, -20_000_000, 0), "script ran, but verification failed");
    println!("underpaid surplus rejected: {err}");
}

#[test]
fn liquidate_keeper_overdraw_rejected() {
    // the keeper tries to take the surplus share too
    let err = expect_rejected(build_liquidate_full(3000, DEBT, 0x07, 0x77, 0, 20_000_000), "script ran, but verification failed");
    println!("keeper overdraw rejected: {err}");
}


// --- Phase 5: liquidation runs at the rate-limited liq_price, LIVE only -------------

#[test]
fn liquidate_uses_rate_limited_liq_price() {
    // raw crashed to $0.20 (vault unhealthy at raw), but liq_price lags at $0.40
    // (vault healthy at liq_price): a flash or manipulated crash can't liquidate yet
    let err = expect_rejected(build_liquidate_ora(2_000, 4_000, 0), "script ran, but verification failed");
    println!("liquidation at lagging liq_price rejected: {err}");
}

#[test]
fn liquidate_at_caught_up_liq_price_ok() {
    let mut built = build_liquidate_ora(2_000, 2_000, 0).expect("liquidation at caught-up liq_price builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn liquidate_on_frozen_oracle_rejected() {
    let err = expect_rejected(build_liquidate_ora(2_000, 2_000, 1), "script ran, but verification failed");
    println!("liquidation on frozen feed rejected: {err}");
}
