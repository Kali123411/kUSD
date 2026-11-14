// Task 4 + review fix pass: vault mint/repay with USD-denominated debt.
// Tx shapes:
//   mint:  inputs [vault, kusd_authority, oracle]      outputs [vault', auth', emitted, oracle']
//   repay: inputs [vault, kusd_authority, kusd_holder] outputs [vault', auth']
// The vault observes and fully pins both the kusd family and the oracle
// passthrough; the kusd authority runs `emission`, which must authenticate the
// gate vault's WIRING (its kusd_id is this group, its oracle_id is the anchored
// feed), not just its template — review findings C1/C2.

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{budget_state, demo_keypair, demo_outpoint, meter, meter_expect_err, sign_input, vault_bundle, gate_setup};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const KUSD_COVID: [u8; 32] = [0x42; 32];
const KUSD_B_COVID: [u8; 32] = [0x43; 32]; // an unrelated second token family
const ORACLE_COVID: [u8; 32] = [0x07; 32];
const PSM_COVID: [u8; 32] = [0x66; 32];
const VAULT_COVID: [u8; 32] = [0x99; 32];

const ZERO32: [u8; 32] = [0u8; 32];
const SURPLUS_COVID: [u8; 32] = [0x77; 32];
const BUDGET_COVID: [u8; 32] = [0x88; 32];
const BUDGET_LIMIT: i64 = 1_000_000_000;

const COLLATERAL: i64 = 1_000_000_000; // 10 KAS in sompi
const PRICE: i64 = 4_000; // 1e-4 USD/KAS: $0.40 // 40 USD cents per KAS -> collateral is worth $4.00

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

/// borrow_guard is back to plain KCC-20 semantics (zeros while disabled);
/// the oracle anchor lives in the blake3 gate config (extension_commitment).
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

fn vault_state(collateral: i64, debt: i64, oracle_covid: [u8; 32]) -> BTreeMap<String, ArtifactValue> {
    state! {
        owner: xonly(1),
        collateral: collateral,
        debt: debt,
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: oracle_covid.to_vec(),
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

#[derive(Clone, Copy)]
struct MintOpts {
    d: i64,
    price: i64,
    auth_out_amount: Option<i64>,
    emitted_scheme: u8,
    /// covid the vault's oracle_id names (0x07 = the anchored feed)
    oracle_covid_byte: u8,
    /// covid of the oracle BOX in the tx (differs to test a mismatched input)
    oracle_box_covid_byte: u8,
    /// emission gate_idx (0 = the vault input; 2 = the oracle input, not a vault)
    gate_idx: i64,
    /// corrupt one byte of the config preimage (blake3 must then mismatch)
    tamper_config: bool,
    /// claim the gate is a PSM (against a vault input, must fail)
    gate_is_psm: bool,
    /// add a second, unrelated kusd family whose authority also runs `emission`
    /// pointing at the same vault (C1: the vault pins group A, not group B)
    rider: bool,
    /// oracle: rate-limited mint price (None = raw price) and status (0 live, 1 frozen, 2 settled)
    ora_mint: Option<i64>,
    ora_status: i64,
    /// budget: balance, the budget box's DAA score (= the clock), omit it entirely,
    /// the d the budget's own meter claims, and the covid the VAULT names for it
    budget_available: i64,
    budget_daa: u64,
    budget_skip: bool,
    meter_d: Option<i64>,
    vault_budget_byte: u8,
}

impl Default for MintOpts {
    fn default() -> Self {
        MintOpts {
            d: 200,
            price: PRICE,
            auth_out_amount: None,
            emitted_scheme: 0x00,
            oracle_covid_byte: 0x07,
            oracle_box_covid_byte: 0x07,
            gate_idx: 0,
            tamper_config: false,
            gate_is_psm: false,
            rider: false,
            ora_mint: None,
            ora_status: 0,
            budget_available: BUDGET_LIMIT,
            budget_daa: 0,
            budget_skip: false,
            meter_d: None,
            vault_budget_byte: 0x88,
        }
    }
}

fn build_mint(opts: MintOpts) -> Result<Built, String> {
    let compiled = vault_bundle();
    let runtime = compiled.runtime_bundle().expect("runtime bundle");
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let mut cfg_psm = gate.psm_template.clone();
    if opts.tamper_config {
        cfg_psm[0] ^= 1;
    }
    let (gate_plen, gate_slen) = if opts.gate_is_psm { (gate.psm_prefix_len, gate.psm_suffix_len) } else { (gate.vault_prefix_len, gate.vault_suffix_len) };

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let oracle_covid = Hash::from_bytes([opts.oracle_box_covid_byte; 32]);
    let vault_covid = Hash::from_bytes(VAULT_COVID);

    let d = opts.d;
    let owner = xonly(1);
    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000; // $10,000 un-issued supply
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(opts.auth_out_amount.unwrap_or(auth_amount - d), &gov, 0x10u8, &gate.ext);
    let emitted = kusd_state(d, &owner, opts.emitted_scheme, &gate.ext);
    let ora = kusd_v2_harness::oracle_state_full(opts.price, opts.ora_mint.unwrap_or(opts.price), opts.price, 0, opts.ora_status);
    let mut vault_in = vault_state(COLLATERAL, 0, [opts.oracle_covid_byte; 32]);
    let mut vault_out = vault_state(COLLATERAL, d, [opts.oracle_covid_byte; 32]);
    vault_in.insert("budget_id".into(), ArtifactValue::Bytes(vec![opts.vault_budget_byte; 32]));
    vault_out.insert("budget_id".into(), ArtifactValue::Bytes(vec![opts.vault_budget_byte; 32]));

    let vault_value_in: u64 = DUST + COLLATERAL as u64 + 200_000_000; // tombstone + collateral + surplus
    let vault_value_out: u64 = DUST + COLLATERAL as u64 + 100_000_000; // surplus pays the emitted box

    let vault_utxo = builder
        .covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value_in, 0, false, Some(vault_covid))
        .expect("vault utxo");
    let auth_utxo = builder
        .covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid))
        .expect("auth utxo");
    let ora_utxo = builder
        .covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(oracle_covid))
        .expect("oracle utxo");
    // global mint budget at input 3; its own DAA score (0) serves as the clock
    let budget_covid = Hash::from_bytes([opts.vault_budget_byte; 32]);
    let now = opts.budget_daa as i64;
    let b_in = budget_state(BUDGET_LIMIT, opts.budget_available, 0, KUSD_COVID);
    let meter_d = opts.meter_d.unwrap_or(d);
    let b_out = budget_state(BUDGET_LIMIT, kusd_v2_harness::budget_refill(BUDGET_LIMIT, opts.budget_available, 0, now) - d, now, KUSD_COVID);
    let b_utxo = builder
        .covenant_utxo("budget_app::Budget", b_in.clone(), DUST, opts.budget_daa, false, Some(budget_covid))
        .expect("budget utxo");

    let owner_kp = demo_keypair(1);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let gate_args = (opts.gate_idx, gate_plen, gate_slen);
    let cfg = (gate.vault_template.clone(), cfg_psm.clone(), gate.oracle_covid.clone(), gate.psm_covid.clone(), gate.surplus_covid.clone(), gate.budget_covid.clone(), opts.gate_is_psm);

    let mut context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("mint").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(d)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            demo_outpoint(0x31, 0),
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _input_idx| {
                vec![
                    ArgValue::Value(emission_states.clone()),
                    ArgValue::Value(ArtifactValue::Int(gate_args.0)),
                    ArgValue::Value(ArtifactValue::Int(gate_args.1)),
                    ArgValue::Value(ArtifactValue::Int(gate_args.2)),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.0.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.1.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.2.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.3.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.4.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.5.clone())),
                    ArgValue::Value(ArtifactValue::Bool(cfg.6)),
                ]
            }),
            demo_outpoint(0x32, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0x33, 0), ora_utxo.clone(), 0);
    let mut entries = vec![vault_utxo, auth_utxo, ora_utxo];
    if !opts.budget_skip {
        context = context.actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(meter_d)), ArgValue::Value(ArtifactValue::Int(3)), ArgValue::Value(ArtifactValue::Bytes(xonly(1)))]),
            demo_outpoint(0x3B, 0),
            b_utxo.clone(),
            0,
        );
        entries.push(b_utxo);
    }

    // Optional unrelated family B whose authority claims the same vault as gate.
    let rider = if opts.rider {
        let kusd_b_covid = Hash::from_bytes(KUSD_B_COVID);
        let attacker = xonly(9);
        let b_auth_in = kusd_state(1_000_000, &gov, 0x10u8, &gate.ext);
        let b_auth_out = b_auth_in.clone();
        let b_emitted = kusd_state(1_000_000, &attacker, 0u8, &gate.ext);
        let b_auth_utxo = builder
            .covenant_utxo("kusd_app::Kusd", b_auth_in.clone(), DUST, 0, false, Some(kusd_b_covid))
            .expect("rider auth utxo");
        let b_states = ArtifactValue::Array(vec![obj(b_auth_out.clone()), obj(b_emitted.clone())]);
        let b_cfg = (gate.vault_template.clone(), gate.psm_template.clone(), gate.oracle_covid.clone(), gate.psm_covid.clone(), gate.surplus_covid.clone(), gate.budget_covid.clone());
        context = context.actor_input(
            "kusd_app::Kusd",
            b_auth_in,
            EntryCall::new("emission").args_with(move |_tx, _input_idx| {
                vec![
                    ArgValue::Value(b_states.clone()),
                    ArgValue::Value(ArtifactValue::Int(0)), // the same vault, which pins group A
                    ArgValue::Value(ArtifactValue::Int(gate_args.1)),
                    ArgValue::Value(ArtifactValue::Int(gate_args.2)),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.0.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.1.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.2.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.3.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.4.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(b_cfg.5.clone())),
                    ArgValue::Value(ArtifactValue::Bool(false)),
                ]
            }),
            demo_outpoint(0x34, 0),
            b_auth_utxo.clone(),
            0,
        );
        Some((b_auth_utxo, b_auth_out, b_emitted, kusd_b_covid))
    } else {
        None
    };

    context = context
        .actor_output("vault_app::Vault", vault_out, CovenantBinding::new(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, oracle_covid), DUST);
    if !opts.budget_skip {
        context = context.actor_output("budget_app::Budget", b_out, CovenantBinding::new(3, budget_covid), DUST);
    }

    if let Some((b_auth_utxo, b_auth_out, b_emitted, kusd_b_covid)) = rider {
        context = context
            .actor_output("kusd_app::Kusd", b_auth_out, CovenantBinding::new(4, kusd_b_covid), DUST)
            .actor_output("kusd_app::Kusd", b_emitted, CovenantBinding::new(4, kusd_b_covid), DUST);
        entries.push(b_auth_utxo);
    }

    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries })
}

/// Build a repay of `r` cents against (COLLATERAL, debt=200), burning a holder
/// box of `holder_amount`; the vault continuation keeps `next_collateral`.
fn build_repay(r: i64, holder_amount: i64, next_collateral: i64) -> Result<Built, String> {
    let compiled = vault_bundle();
    let runtime = compiled.runtime_bundle().expect("runtime bundle");
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);

    let kusd_covid = Hash::from_bytes(KUSD_COVID);
    let owner = xonly(1);
    let gov = xonly(5);
    let auth_amount: i64 = 999_800;
    let auth_in = kusd_state(auth_amount, &gov, 0x10u8, &gate.ext);
    let auth_out = kusd_state(auth_amount + r, &gov, 0x10u8, &gate.ext);
    let holder = kusd_state(holder_amount, &owner, 0u8, &gate.ext);
    let vault_in = vault_state(COLLATERAL, 200, ORACLE_COVID);
    let vault_out = vault_state(next_collateral, 200 - r, ORACLE_COVID);

    let vault_value_in: u64 = DUST + COLLATERAL as u64 + 100_000_000;
    let vault_value_out: u64 = DUST + next_collateral as u64;

    let vault_utxo = builder
        .covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value_in, 0, false, Some(Hash::from_bytes(VAULT_COVID)))
        .expect("vault utxo");
    let auth_utxo = builder
        .covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(kusd_covid))
        .expect("auth utxo");
    let holder_utxo = builder
        .covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(kusd_covid))
        .expect("holder utxo");

    let owner_kp = demo_keypair(1);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let gate_args = (gate.vault_prefix_len, gate.vault_suffix_len);
    let cfg = (gate.vault_template.clone(), gate.psm_template.clone(), gate.oracle_covid.clone(), gate.psm_covid.clone(), gate.surplus_covid.clone(), gate.budget_covid.clone());

    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("repay").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(r)),
                    ArgValue::Value(ArtifactValue::Int(next_collateral)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            demo_outpoint(0x41, 0),
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
                    ArgValue::Value(ArtifactValue::Int(gate_args.0)),
                    ArgValue::Value(ArtifactValue::Int(gate_args.1)),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.0.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.1.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.2.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.3.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.4.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(cfg.5.clone())),
                    ArgValue::Value(ArtifactValue::Bool(false)),
                ]
            }),
            demo_outpoint(0x42, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(1))))]
            }),
            demo_outpoint(0x43, 0),
            holder_utxo.clone(),
            0,
        )
        .actor_output("vault_app::Vault", vault_out, CovenantBinding::new(0, Hash::from_bytes(VAULT_COVID)), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, kusd_covid), 2 * DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r }, 3, BUDGET_COVID, KUSD_COVID, BUDGET_LIMIT, BUDGET_LIMIT - 1_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![vault_utxo, auth_utxo, holder_utxo, b_utxo] })
}

#[test]
fn mint_healthy_ok_and_metered() {
    // $4.00 collateral at MIN_RATIO 175% caps debt at 228 cents; mint 200 is healthy
    let mut built = build_mint(MintOpts::default()).expect("healthy mint builds");
    let report = meter(&mut built.tx, built.entries);
    println!("MINT: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn mint_undercollateralized_rejected() {
    let err = expect_rejected(build_mint(MintOpts { d: 300, ..Default::default() }), "script ran, but verification failed");
    println!("undercollateralized rejected: {err}");
}

#[test]
fn mint_authority_delta_mismatch_rejected() {
    // family claims the authority only gave up d-1
    let err = expect_rejected(
        build_mint(MintOpts { auth_out_amount: Some(1_000_000 - 199), ..Default::default() }),
        "script ran, but verification failed",
    );
    println!("authority delta mismatch rejected: {err}");
}

#[test]
fn mint_emitted_authority_scheme_rejected() {
    let err = expect_rejected(build_mint(MintOpts { emitted_scheme: 0x10, ..Default::default() }), "script ran, but verification failed");
    println!("emitted authority scheme rejected: {err}");
}

#[test]
fn mint_amount_bound_rejected() {
    let err = expect_rejected(build_mint(MintOpts { d: 1 << 62, ..Default::default() }), "script ran, but verification failed");
    println!("amount bound rejected: {err}");
}

// --- review finding I1: the emission gate's own threat model ---

#[test]
fn emission_other_group_rider_rejected() {
    // review C1: an unrelated family's authority must not be able to emit by
    // pointing its gate at a vault that pins a DIFFERENT kusd group
    let err = expect_rejected(build_mint(MintOpts { rider: true, ..Default::default() }), "script ran, but verification failed");
    println!("other-group rider rejected: {err}");
}

#[test]
fn mint_untrusted_oracle_wiring_rejected() {
    // review C2: a vault whose oracle_id names a feed other than the anchored
    // one must not satisfy the emission gate, however healthy it looks there
    let err = expect_rejected(
        build_mint(MintOpts { d: 10_000, price: 100_000_000, oracle_covid_byte: 0x08, oracle_box_covid_byte: 0x08, ..Default::default() }),
        "script ran, but verification failed",
    );
    println!("untrusted oracle wiring rejected: {err}");
}

#[test]
fn emission_gate_not_a_vault_rejected() {
    // gate_idx pointing at a non-vault input must fail inside the authority's
    // script (here: the template slice aborts on the too-short revealed script)
    let err = expect_rejected(build_mint(MintOpts { gate_idx: 2, ..Default::default() }), "input 1 script failed");
    println!("non-vault gate rejected: {err}");
}

#[test]
fn mint_forged_oracle_input_rejected() {
    // honest vault wiring, but the oracle box in the tx is under a different
    // covid: the vault's observe-by-covid must find no oracle input
    let err = expect_rejected(
        build_mint(MintOpts { oracle_box_covid_byte: 0x08, ..Default::default() }),
        "expects 1 inputs for its covenant id",
    );
    println!("forged oracle input rejected: {err}");
}

#[test]
fn emission_wrong_config_rejected() {
    // Review Focus 4: a config preimage whose blake3 != extension_commitment
    let err = expect_rejected(build_mint(MintOpts { tamper_config: true, ..Default::default() }), "input 1 script failed");
    println!("wrong config rejected: {err}");
}

#[test]
fn emission_gate_kind_mismatch_rejected() {
    // claiming the vault input is a PSM gate must fail the psm-template read
    let err = expect_rejected(build_mint(MintOpts { gate_is_psm: true, ..Default::default() }), "input 1 script failed");
    println!("gate kind mismatch rejected: {err}");
}

// --- repay ---

#[test]
fn repay_reduces_debt_and_restores_supply() {
    // partial repay leaving debt 100 == MIN_DEBT (review I4: smaller remainders are dust)
    let mut built = build_repay(100, 100, COLLATERAL).expect("repay builds");
    let report = meter(&mut built.tx, built.entries);
    println!("REPAY: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn repay_dust_debt_remainder_rejected() {
    // review I4: a partial repay may not leave 0 < debt < MIN_DEBT
    let err = expect_rejected(build_repay(150, 150, COLLATERAL), "script ran, but verification failed");
    println!("dust debt remainder rejected: {err}");
}

#[test]
fn repay_burn_amount_mismatch_rejected() {
    // holder box only carries 150 but the vault claims r=200
    let err = expect_rejected(build_repay(200, 150, COLLATERAL), "script ran, but verification failed");
    println!("burn amount mismatch rejected: {err}");
}

#[test]
fn repay_full_releases_collateral() {
    // review I4 (v1 parity): once debt hits 0 the owner may take the collateral
    let mut built = build_repay(200, 200, 0).expect("full repay with release builds");
    let report = meter(&mut built.tx, built.entries);
    println!("REPAY-RELEASE: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn repay_partial_cannot_release_collateral() {
    // while indebted, the collateral is frozen
    let err = expect_rejected(build_repay(100, 100, COLLATERAL - 1), "script ran, but verification failed");
    println!("partial-repay release rejected: {err}");
}


// --- Phase 5: rate-limited prices, oracle status, global mint budget ---------------

#[test]
fn mint_uses_rate_limited_mint_price() {
    // raw price $0.40 makes 200c healthy (needs 350c of collateral: 10 KAS = 400c),
    // but the rate-limited mint price lags at $0.30 (300c) -> unhealthy, refused
    let err = expect_rejected(build_mint(MintOpts { ora_mint: Some(3_000), ..Default::default() }), "script ran, but verification failed");
    println!("mint at lagging mint_price rejected: {err}");
}

#[test]
fn mint_on_frozen_oracle_rejected() {
    let err = expect_rejected(build_mint(MintOpts { ora_status: 1, ..Default::default() }), "script ran, but verification failed");
    println!("mint on frozen feed rejected: {err}");
}

#[test]
fn mint_on_settled_oracle_rejected() {
    let err = expect_rejected(build_mint(MintOpts { ora_status: 2, ..Default::default() }), "script ran, but verification failed");
    println!("mint on settled feed rejected: {err}");
}

#[test]
fn mint_over_budget_rejected() {
    // only 150c of issuance left in the bucket, mint asks for 200c
    let err = expect_rejected(build_mint(MintOpts { budget_available: 150, ..Default::default() }), "script ran, but verification failed");
    println!("over-budget mint rejected: {err}");
}

#[test]
fn mint_budget_refills_over_time() {
    // empty bucket at last_refill 0; a full day later (clock DAA 864000) it is full again
    let mut built = build_mint(MintOpts { budget_available: 0, budget_daa: 864_000, ..Default::default() }).expect("refilled budget mint builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn mint_without_budget_rejected() {
    // issuance must always be metered: the vault's budget observe needs the box
    let err = expect_rejected(build_mint(MintOpts { budget_skip: true, ..Default::default() }), "observe `budget` expects 1 inputs");
    println!("unmetered mint rejected: {err}");
}

#[test]
fn mint_budget_meter_underclaim_rejected() {
    // the budget's own meter claims 1c while the vault mints 200c: the two pins disagree
    let err = expect_rejected(build_mint(MintOpts { meter_d: Some(1), ..Default::default() }), "script ran, but verification failed");
    println!("meter under-claim rejected: {err}");
}

#[test]
fn mint_with_parallel_budget_rejected() {
    // a vault naming its own (genuine-template, attacker-owned) budget box cannot gate:
    // the emission config pins THE budget covid
    let err = expect_rejected(build_mint(MintOpts { vault_budget_byte: 0x89, ..Default::default() }), "script ran, but verification failed");
    println!("parallel-budget mint rejected: {err}");
}
