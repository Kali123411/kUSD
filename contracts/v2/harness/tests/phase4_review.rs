// Phase 4 security-review fix pass — each test is the reviewer's attack
// transaction, expected REJECTED after the fix (RED: accepted before it).
//
//   C1: one kUSD burn credited to multiple burn-observing entries in one tx
//       (two repays sharing a burn; repay + psm swap_out sharing a burn).
//       Fix: every kusd-observing vault/psm entry pins itself to tx input 0.
//   C2: attacker-authored vault surplus_id (bogus covid) -> unliquidatable
//       vault. Fix: surplus covid joins the gate config (160-byte preimage),
//       emission checks gate.surplus_id.
//   I3: owner scheme 0x04 (presence-as-consent) rejected on kUSD outputs
//       (declared deviation — every protocol covid is permissionlessly
//       co-spendable here).
//   I4: dust vaults — mint/adjust require collateral > TOMBSTONE and
//       debt >= MIN_DEBT; liquidate clamps the keeper payout up to DUST.

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
const VAULT_A: [u8; 32] = [0x99; 32];
const VAULT_B: [u8; 32] = [0x9A; 32];
const ZERO32: [u8; 32] = [0u8; 32];
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

fn vault_state(collateral: i64, debt: i64, surplus_covid: [u8; 32]) -> BTreeMap<String, ArtifactValue> {
    state! {
        owner: xonly(1),
        collateral: collateral,
        debt: debt,
        kusd_id: KUSD_COVID.to_vec(),
        oracle_id: ORACLE_COVID.to_vec(),
        surplus_id: surplus_covid.to_vec(),
        budget_id: BUDGET_COVID.to_vec(),
    }
}

fn oracle_state(price: i64) -> BTreeMap<String, ArtifactValue> {
    kusd_v2_harness::oracle_state_v2(price)
}

fn psm_state(ceiling: i64, minted: i64) -> BTreeMap<String, ArtifactValue> {
    state! {
        ceiling_cents: ceiling,
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

const BUDGET_LIMIT: i64 = 1_000_000_000;

/// Append the global mint budget as input `idx` (also the clock) metering `d`.
fn add_budget<'a>(context: TxContext<'a>, builder: &TxBuilder<'_>, d: i64, idx: u16) -> (TxContext<'a>, kaspa_consensus_core::tx::UtxoEntry) {
    let budget_covid = Hash::from_bytes(BUDGET_COVID);
    let b_in = kusd_v2_harness::budget_state(BUDGET_LIMIT, BUDGET_LIMIT, 0, KUSD_COVID);
    let b_out = kusd_v2_harness::budget_state(BUDGET_LIMIT, BUDGET_LIMIT - d, 0, KUSD_COVID);
    let b_utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), DUST, 0, false, Some(budget_covid)).expect("budget utxo");
    let i = idx as i64;
    let context = context
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(d)), ArgValue::Value(ArtifactValue::Int(i)), ArgValue::Value(ArtifactValue::Bytes(xonly(1)))]),
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

fn repay_call(r: i64, next_collateral: i64, clock_idx: i64) -> EntryCall<'static> {
    let kp = demo_keypair(1);
    EntryCall::new("repay").args_with(move |tx, input_idx| {
        vec![
            ArgValue::Value(ArtifactValue::Int(r)),
            ArgValue::Value(ArtifactValue::Int(next_collateral)),
            ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp))),
            ArgValue::Value(ArtifactValue::Int(clock_idx)),
        ]
    })
}

fn delegator_call(key: u8) -> EntryCall<'static> {
    EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
        vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &demo_keypair(key))))]
    })
}

// --- C1-A: two repays, one burn ---------------------------------------------------

fn build_two_repays_one_burn() -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let r: i64 = 200;
    let collateral: i64 = 1_000_000_000;

    let gov = xonly(5);
    let auth_amount: i64 = 999_600; // two mints of 200 happened
    let auth_in = kusd_state(auth_amount, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(auth_amount + r, &gov, 0x10, &gate.ext); // ONE burn credited
    let holder = kusd_state(r, &xonly(1), 0x00, &gate.ext);
    let va_in = vault_state(collateral, r, SURPLUS_COVID);
    let vb_in = vault_state(collateral, r, SURPLUS_COVID);
    let va_out = vault_state(0, 0, SURPLUS_COVID);
    let vb_out = vault_state(0, 0, SURPLUS_COVID);

    let vault_value_in = TOMBSTONE + collateral as u64;
    let va_utxo = builder.covenant_utxo("vault_app::Vault", va_in.clone(), vault_value_in, 0, false, Some(Hash::from_bytes(VAULT_A))).expect("va");
    let vb_utxo = builder.covenant_utxo("vault_app::Vault", vb_in.clone(), vault_value_in, 0, false, Some(Hash::from_bytes(VAULT_B))).expect("vb");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("auth");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("holder");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let context = TxContext::new()
        .actor_input("vault_app::Vault", va_in, repay_call(r, 0, 4), demo_outpoint(0xF1, 0), va_utxo.clone(), 0)
        .actor_input("vault_app::Vault", vb_in, repay_call(r, 0, 4), demo_outpoint(0xF2, 0), vb_utxo.clone(), 0)
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            demo_outpoint(0xF3, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("kusd_app::Kusd", holder, delegator_call(1), demo_outpoint(0xF4, 0), holder_utxo.clone(), 0)
        .actor_output("vault_app::Vault", va_out, CovenantBinding::new(0, Hash::from_bytes(VAULT_A)), TOMBSTONE)
        .actor_output("vault_app::Vault", vb_out, CovenantBinding::new(1, Hash::from_bytes(VAULT_B)), TOMBSTONE)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(2, Hash::from_bytes(KUSD_COVID)), 2 * DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r }, 4, BUDGET_COVID, KUSD_COVID, BUDGET_LIMIT, BUDGET_LIMIT - 1_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![va_utxo, vb_utxo, auth_utxo, holder_utxo, b_utxo] })
}

#[test]
fn burn_double_credit_two_repays_rejected() {
    // reviewer C1 attack A: ONE 200c burn clears TWO 200c debts
    let err = expect_rejected(build_two_repays_one_burn(), "");
    println!("two-repays-one-burn rejected: {err}");
}

// --- C1-B: repay + psm swap_out, one burn -----------------------------------------

fn build_repay_plus_swap_out_one_burn() -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let c: i64 = 200;
    let collateral: i64 = 1_000_000_000;

    let gov = xonly(5);
    let auth_amount: i64 = 999_600;
    let auth_in = kusd_state(auth_amount, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(auth_amount + c, &gov, 0x10, &gate.ext);
    let holder = kusd_state(c, &xonly(1), 0x00, &gate.ext);
    let v_in = vault_state(collateral, c, SURPLUS_COVID);
    let v_out = vault_state(0, 0, SURPLUS_COVID);
    let psm_in = psm_state(100_000, c);
    let psm_out = psm_state(100_000, 0);
    let ora = oracle_state(PRICE);

    let kas_out = (kusd_v2_harness::sompi_of(c, PRICE)) as u64;
    let psm_value_in: u64 = TOMBSTONE + 2_000_000_000;
    let vault_value_in = TOMBSTONE + collateral as u64;

    let v_utxo = builder.covenant_utxo("vault_app::Vault", v_in.clone(), vault_value_in, 0, false, Some(Hash::from_bytes(VAULT_A))).expect("v");
    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value_in, 0, false, Some(Hash::from_bytes(PSM_COVID))).expect("psm");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("auth");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("holder");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(Hash::from_bytes(ORACLE_COVID))).expect("ora");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let redeemer = xonly(1);
    let burner_kp = demo_keypair(1);
    let mut payout_spk = vec![0x20];
    payout_spk.extend_from_slice(&xonly(1));
    payout_spk.push(0xac);
    let context = TxContext::new()
        .actor_input("vault_app::Vault", v_in, repay_call(c, 0, 5), demo_outpoint(0xF5, 0), v_utxo.clone(), 0)
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_out").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner_kp))),
                    ArgValue::Value(ArtifactValue::Int(5)),
                ]
            }),
            demo_outpoint(0xF6, 0),
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            demo_outpoint(0xF7, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("kusd_app::Kusd", holder, delegator_call(1), demo_outpoint(0xF8, 0), holder_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xF9, 0), ora_utxo.clone(), 0)
        .actor_output("vault_app::Vault", v_out, CovenantBinding::new(0, Hash::from_bytes(VAULT_A)), TOMBSTONE)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(2, Hash::from_bytes(KUSD_COVID)), 2 * DUST)
        .output(kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, payout_spk), None, kas_out)
        .actor_output("psm_app::Psm", psm_out, CovenantBinding::new(1, Hash::from_bytes(PSM_COVID)), psm_value_in - kas_out)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(4, Hash::from_bytes(ORACLE_COVID)), DUST);
    let (context, b_utxo) = kusd_v2_harness::add_budget(context, &builder, kusd_v2_harness::BudgetUse::Credit { r: c }, 5, BUDGET_COVID, KUSD_COVID, BUDGET_LIMIT, BUDGET_LIMIT - 1_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![v_utxo, psm_utxo, auth_utxo, holder_utxo, ora_utxo, b_utxo] })
}

#[test]
fn burn_double_credit_repay_plus_swap_out_rejected() {
    // reviewer C1 attack B: one burn clears a vault debt AND drains the reserve
    let err = expect_rejected(build_repay_plus_swap_out_one_burn(), "");
    println!("repay+swap_out-one-burn rejected: {err}");
}

// --- C2: bogus vault surplus_id ----------------------------------------------------

fn build_mint_with_surplus_id(surplus_covid: [u8; 32]) -> Result<Built, String> {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let d: i64 = 200;
    let collateral: i64 = 1_000_000_000;

    let gov = xonly(5);
    let auth_amount: i64 = 1_000_000;
    let auth_in = kusd_state(auth_amount, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(auth_amount - d, &gov, 0x10, &gate.ext);
    let emitted = kusd_state(d, &xonly(1), 0x00, &gate.ext);
    let v_in = vault_state(collateral, 0, surplus_covid);
    let v_out = vault_state(collateral, d, surplus_covid);
    let ora = oracle_state(PRICE);

    let vault_value_in = TOMBSTONE + collateral as u64 + 200_000_000;
    let v_utxo = builder.covenant_utxo("vault_app::Vault", v_in.clone(), vault_value_in, 0, false, Some(Hash::from_bytes(VAULT_A))).expect("v");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("auth");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(Hash::from_bytes(ORACLE_COVID))).expect("ora");

    let owner_kp = demo_keypair(1);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            v_in,
            EntryCall::new("mint").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(d)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            demo_outpoint(0xFA, 0),
            v_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            demo_outpoint(0xFB, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xFC, 0), ora_utxo.clone(), 0)
        .actor_output("vault_app::Vault", v_out, CovenantBinding::new(0, Hash::from_bytes(VAULT_A)), TOMBSTONE + collateral as u64)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, Hash::from_bytes(KUSD_COVID)), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, Hash::from_bytes(KUSD_COVID)), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, Hash::from_bytes(ORACLE_COVID)), DUST);
    let (context, b_utxo) = add_budget(context, &builder, d, 3);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![v_utxo, auth_utxo, ora_utxo, b_utxo] })
}

#[test]
fn mint_with_bogus_surplus_id_rejected() {
    // reviewer C2: a vault wired to a nonexistent surplus covid could mint but
    // never be liquidated — the gate config must pin the surplus instance
    let err = expect_rejected(build_mint_with_surplus_id([0xAB; 32]), "script ran, but verification failed");
    println!("bogus-surplus-id mint rejected: {err}");
}

#[test]
fn mint_with_genuine_surplus_id_ok() {
    let mut built = build_mint_with_surplus_id(SURPLUS_COVID).expect("genuine mint builds");
    meter(&mut built.tx, built.entries);
}

// --- I4: dust vaults ---------------------------------------------------------------

#[test]
fn mint_dust_collateral_rejected() {
    // collateral == TOMBSTONE -> freed_max == 0 -> unliquidatable: must not mint
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("tx builder");
    let gate = gate_setup(ORACLE_COVID, PSM_COVID, SURPLUS_COVID, BUDGET_COVID);
    let d: i64 = 200;
    let collateral: i64 = TOMBSTONE as i64; // dust vault: health passes at price 4000
    let gov = xonly(5);
    let auth_in = kusd_state(1_000_000, &gov, 0x10, &gate.ext);
    let auth_out = kusd_state(1_000_000 - d, &gov, 0x10, &gate.ext);
    let emitted = kusd_state(d, &xonly(1), 0x00, &gate.ext);
    let v_in = vault_state(collateral, 0, SURPLUS_COVID);
    let v_out = vault_state(collateral, d, SURPLUS_COVID);
    let ora = oracle_state(400_000); // $40/KAS (1e-4 USD units): 1 KAS collateral = $40 >> $3.50 needed

    let v_utxo = builder.covenant_utxo("vault_app::Vault", v_in.clone(), TOMBSTONE + collateral as u64 + 200_000_000, 0, false, Some(Hash::from_bytes(VAULT_A))).expect("v");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), DUST, 0, false, Some(Hash::from_bytes(KUSD_COVID))).expect("auth");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), DUST, 0, false, Some(Hash::from_bytes(ORACLE_COVID))).expect("ora");
    let owner_kp = demo_keypair(1);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            v_in,
            EntryCall::new("mint").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(d)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &owner_kp))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            demo_outpoint(0xFD, 0),
            v_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            demo_outpoint(0xFE, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", demo_outpoint(0xFF, 0), ora_utxo.clone(), 0)
        .actor_output("vault_app::Vault", v_out, CovenantBinding::new(0, Hash::from_bytes(VAULT_A)), TOMBSTONE + collateral as u64)
        .actor_output("kusd_app::Kusd", auth_out, CovenantBinding::new(1, Hash::from_bytes(KUSD_COVID)), DUST)
        .actor_output("kusd_app::Kusd", emitted, CovenantBinding::new(1, Hash::from_bytes(KUSD_COVID)), DUST)
        .actor_output("oracle_app::Oracle", ora, CovenantBinding::new(2, Hash::from_bytes(ORACLE_COVID)), DUST);
    let (context, b_utxo) = add_budget(context, &builder, d, 3);
    let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries: vec![v_utxo, auth_utxo, ora_utxo, b_utxo] });
    let err = expect_rejected(result, "script ran, but verification failed");
    println!("dust-collateral mint rejected: {err}");
}
