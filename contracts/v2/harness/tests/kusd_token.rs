// Phase 4 Task 2: KCC-20 witness-ABI kUSD token — KCC-2 owner schemes
// (0x00–0x04, authority marker 0x10), borrow schemes 0x00–0x03, witness-blob
// transfer with a self-authorizing transfer_delegator (the check-free `join`
// delegate is REMOVED: argent delegation authenticates the actor, not the
// entry — leader-delegate invariant Property 7).

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{
    borrow_witness, build_app, delegate_witness_p2pk, demo_keypair, demo_outpoint, meter,
    meter_expect_err, owner_witness_p2pk,
};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const EXT: [u8; 32] = [0xEE; 32];
const ZERO32: [u8; 32] = [0u8; 32];

const S_P2PK: u8 = 0x00; // KCC-2 OWNER_P2PK_SCHNORR
const S_AUTH: u8 = 0x10; // kUSD authority marker (declared out-of-range extension)
const B_NONE: u8 = 0x00; // BORROW_DISABLED
const B_THRESH: u8 = 0x01;
const B_SIG: u8 = 0x02;
const B_CHAIN: u8 = 0x03;

fn kusd_state(amount: i64, owner: &[u8], scheme: u8, borrow: u8, guard: &[u8; 32]) -> BTreeMap<String, ArtifactValue> {
    state! {
        amount: amount,
        owner: owner.to_vec(),
        owner_scheme: scheme,
        borrow_scheme: borrow,
        borrow_guard: guard.to_vec(),
        extension_commitment: EXT.to_vec(),
    }
}

fn plain(amount: i64, owner: &[u8]) -> BTreeMap<String, ArtifactValue> {
    kusd_state(amount, owner, S_P2PK, B_NONE, &ZERO32)
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

struct Family {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<kaspa_consensus_core::tx::UtxoEntry>,
}

fn expect_rejected(result: Result<Family, String>, expect: &str) -> String {
    let err = match result {
        Err(build_err) => build_err,
        Ok(mut fam) => meter_expect_err(&mut fam.tx, fam.entries),
    };
    assert!(err.contains(expect), "rejected for the wrong reason: wanted '{expect}' in '{err}'");
    err
}

/// Leader (key `a`) + sibling delegate (key `b`, self-authorizing) -> 2 outputs.
fn build_transfer_2x2(
    leader_amount: i64,
    leader_scheme: u8,
    out_amounts: [i64; 2],
    out_schemes: [u8; 2],
    out_values: [u64; 2],
    sign_keys: [u8; 2],
) -> Result<Family, String> {
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes([0x42; 32]);

    let a = xonly(1);
    let b = xonly(2);
    let leader_state = kusd_state(leader_amount, &a, leader_scheme, B_NONE, &ZERO32);
    let sibling_state = plain(300, &b);
    let out0 = kusd_state(out_amounts[0], &a, out_schemes[0], B_NONE, &ZERO32);
    let out1 = kusd_state(out_amounts[1], &b, out_schemes[1], B_NONE, &ZERO32);

    let leader_utxo = builder
        .covenant_utxo("Kusd", leader_state.clone(), 200_000_000, 0, false, Some(covid))
        .expect("leader utxo");
    let sibling_utxo = builder
        .covenant_utxo("Kusd", sibling_state.clone(), 150_000_000, 0, false, Some(covid))
        .expect("sibling utxo");

    let k_leader = demo_keypair(sign_keys[0]);
    let k_sib = demo_keypair(sign_keys[1]);
    let new_states = ArtifactValue::Array(vec![obj(out0.clone()), obj(out1.clone())]);

    let context = TxContext::new()
        .actor_input(
            "Kusd",
            leader_state,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(new_states.clone()),
                    ArgValue::Value(ArtifactValue::Bytes(owner_witness_p2pk(tx, input_idx, &k_leader))),
                ]
            }),
            demo_outpoint(0x11, 0),
            leader_utxo.clone(),
            0,
        )
        .actor_input(
            "Kusd",
            sibling_state,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(delegate_witness_p2pk(tx, input_idx, &k_sib)))]
            }),
            demo_outpoint(0x12, 0),
            sibling_utxo.clone(),
            0,
        )
        .actor_output("Kusd", out0, CovenantBinding::new(0, covid), out_values[0])
        .actor_output("Kusd", out1, CovenantBinding::new(0, covid), out_values[1]);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Family { tx, entries: vec![leader_utxo, sibling_utxo] })
}

/// 1-in/1-out leader-only transfer; out carries an arbitrary owner scheme/borrow pair.
fn build_transfer_1x1(out_scheme: u8, out_borrow: u8, out_guard: [u8; 32], witness_override: Option<Vec<u8>>) -> Result<Family, String> {
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes([0x42; 32]);

    let a = xonly(1);
    let leader_state = plain(700, &a);
    let out0 = kusd_state(700, &a, out_scheme, out_borrow, &out_guard);
    let leader_utxo = builder
        .covenant_utxo("Kusd", leader_state.clone(), 200_000_000, 0, false, Some(covid))
        .expect("leader utxo");

    let k_leader = demo_keypair(1);
    let new_states = ArtifactValue::Array(vec![obj(out0.clone())]);
    let context = TxContext::new()
        .actor_input(
            "Kusd",
            leader_state,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                let w = witness_override.clone().unwrap_or_else(|| owner_witness_p2pk(tx, input_idx, &k_leader));
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
            }),
            demo_outpoint(0x13, 0),
            leader_utxo.clone(),
            0,
        )
        .actor_output("Kusd", out0, CovenantBinding::new(0, covid), 200_000_000);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Family { tx, entries: vec![leader_utxo] })
}

/// Borrowed receive: leader = recipient's borrow-enabled box (NO owner auth),
/// delegate = payer box (key 2, self-authorized) contributing `pay` cents.
/// `path_witness` builds the borrow-path witness from (tx, leader_idx).
#[allow(clippy::too_many_arguments)]
fn build_borrow(
    leader_scheme: u8,
    borrow: u8,
    guard: [u8; 32],
    out_guard: [u8; 32],
    pay: i64,
    out_leader_delta: i64,
    out_value_delta: i64,
    path_witness: impl Fn(&dyn Fn() -> Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
) -> Result<Family, String> {
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes([0x42; 32]);

    let r = xonly(1); // recipient (does NOT sign)
    let p = xonly(2); // payer
    let leader_state = kusd_state(500, &r, leader_scheme, borrow, &guard);
    let payer_state = plain(pay, &p);
    let out0 = kusd_state(500 + out_leader_delta, &r, leader_scheme, borrow, &out_guard);
    let out1 = kusd_state(pay - out_leader_delta, &p, S_P2PK, B_NONE, &ZERO32);

    let leader_value: u64 = 200_000_000;
    let leader_utxo = builder
        .covenant_utxo("Kusd", leader_state.clone(), leader_value, 0, false, Some(covid))
        .expect("leader utxo");
    let payer_utxo = builder
        .covenant_utxo("Kusd", payer_state.clone(), 150_000_000, 0, false, Some(covid))
        .expect("payer utxo");

    let k_payer = demo_keypair(2);
    let new_states = ArtifactValue::Array(vec![obj(out0.clone()), obj(out1.clone())]);
    let pw = std::sync::Arc::new(path_witness);
    let context = TxContext::new()
        .actor_input(
            "Kusd",
            leader_state,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                // give the witness builder a sighash-signer for THIS input
                let sigher = {
                    let tx_ref = tx;
                    move || kusd_v2_harness::sign_input(tx_ref, input_idx, &demo_keypair(9))
                };
                vec![
                    ArgValue::Value(new_states.clone()),
                    ArgValue::Value(ArtifactValue::Bytes(borrow_witness(pw(&sigher)))),
                ]
            }),
            demo_outpoint(0x14, 0),
            leader_utxo.clone(),
            0,
        )
        .actor_input(
            "Kusd",
            payer_state,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(delegate_witness_p2pk(tx, input_idx, &k_payer)))]
            }),
            demo_outpoint(0x15, 0),
            payer_utxo.clone(),
            0,
        )
        .actor_output("Kusd", out0, CovenantBinding::new(0, covid), (leader_value as i64 + out_value_delta) as u64)
        .actor_output("Kusd", out1, CovenantBinding::new(0, covid), 150_000_000)
        ;
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Family { tx, entries: vec![leader_utxo, payer_utxo] })
}

// --- normal path --------------------------------------------------------------

#[test]
fn transfer_2in_2out_conserves() {
    let mut fam = build_transfer_2x2(700, S_P2PK, [600, 400], [S_P2PK, S_P2PK], [200_000_000, 150_000_000], [1, 2]).expect("valid transfer builds");
    let report = meter(&mut fam.tx, fam.entries);
    println!("TRANSFER 2x2: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
}

#[test]
fn transfer_amount_inflation_rejected() {
    let err = expect_rejected(build_transfer_2x2(700, S_P2PK, [601, 400], [S_P2PK, S_P2PK], [200_000_000, 150_000_000], [1, 2]), "script ran, but verification failed");
    println!("inflation rejected: {err}");
}

#[test]
fn transfer_fee_from_box_value_ok() {
    // amounts conserved; 50M sompi of box value left for fee (KCC-20 semantics:
    // value is NOT exactly conserved, each output >= DUST)
    let mut fam = build_transfer_2x2(700, S_P2PK, [600, 400], [S_P2PK, S_P2PK], [200_000_000, 100_000_000], [1, 2]).expect("fee-paying transfer builds");
    meter(&mut fam.tx, fam.entries);
}

#[test]
fn transfer_wrong_delegate_signer_rejected() {
    let err = expect_rejected(build_transfer_2x2(700, S_P2PK, [600, 400], [S_P2PK, S_P2PK], [200_000_000, 150_000_000], [1, 3]), "script ran, but verification failed");
    println!("wrong delegate signer rejected: {err}");
}

#[test]
fn transfer_wrong_leader_signer_rejected() {
    let err = expect_rejected(build_transfer_2x2(700, S_P2PK, [600, 400], [S_P2PK, S_P2PK], [200_000_000, 150_000_000], [3, 2]), "script ran, but verification failed");
    println!("wrong leader signer rejected: {err}");
}

#[test]
fn transfer_cannot_move_authority_amount() {
    let err = expect_rejected(build_transfer_2x2(700, S_AUTH, [699, 301], [S_AUTH, S_P2PK], [200_000_000, 150_000_000], [1, 2]), "script ran, but verification failed");
    println!("authority amount move rejected: {err}");
}

#[test]
fn transfer_authority_frozen_continuation_ok() {
    let mut fam = build_transfer_2x2(700, S_AUTH, [700, 300], [S_AUTH, S_P2PK], [200_000_000, 150_000_000], [1, 2]).expect("frozen authority continuation builds");
    meter(&mut fam.tx, fam.entries);
}

#[test]
fn transfer_below_dust_value_rejected() {
    let err = expect_rejected(build_transfer_2x2(700, S_P2PK, [600, 400], [S_P2PK, S_P2PK], [250_000_000, DUST - 1], [1, 2]), "script ran, but verification failed");
    println!("dust output rejected: {err}");
}

#[test]
fn transfer_all_owner_schemes_accepted() {
    // D4 (review I3): 0x04 (covenant-id, presence-as-consent) is rejected on
    // kUSD OUTPUTS — every protocol covid here is permissionlessly co-spendable
    for scheme in [0x00u8, 0x01, 0x02, 0x03] {
        let mut fam = build_transfer_1x1(scheme, B_NONE, ZERO32, None)
            .unwrap_or_else(|e| panic!("scheme {scheme:#04x} output must build: {e}"));
        meter(&mut fam.tx, fam.entries);
    }
}

#[test]
fn transfer_invalid_scheme_rejected() {
    for scheme in [0x04u8, 0x05, 0x7f] {
        let err = expect_rejected(build_transfer_1x1(scheme, B_NONE, ZERO32, None), "script ran, but verification failed");
        println!("invalid/deviation scheme {scheme:#04x} rejected: {err}");
    }
}

#[test]
fn transfer_creates_borrow_enabled_box_ok() {
    // output with amount-threshold borrow policy (threshold 0 in guard[0..8])
    let mut fam = build_transfer_1x1(S_P2PK, B_THRESH, ZERO32, None).expect("borrow-enabled output builds");
    meter(&mut fam.tx, fam.entries);
}

#[test]
fn transfer_invalid_borrow_scheme_rejected() {
    let err = expect_rejected(build_transfer_1x1(S_P2PK, 0x04, ZERO32, None), "script ran, but verification failed");
    println!("invalid borrow scheme rejected: {err}");
}

#[test]
fn truncated_witness_rejected() {
    // zero-filled 65-byte witness: sig parse must refuse the hash-type byte
    let err = expect_rejected(build_transfer_1x1(S_P2PK, B_NONE, ZERO32, Some(vec![0x00; 66])), "invalid hash type");
    println!("junk sig witness rejected: {err}");
    // genuinely truncated: path + 39 bytes cannot convert to byte[65]
    let err = expect_rejected(build_transfer_1x1(S_P2PK, B_NONE, ZERO32, Some(vec![0x00; 40])), "");
    println!("short witness rejected: {err}");
}

#[test]
fn empty_witness_rejected() {
    let err = expect_rejected(build_transfer_1x1(S_P2PK, B_NONE, ZERO32, Some(Vec::new())), "script ran, but verification failed");
    println!("empty witness rejected: {err}");
}

// --- borrow path ---------------------------------------------------------------

#[test]
fn borrow_amount_threshold_receive_ok() {
    // guard[0..8] = LE threshold 0; paying 200 into the box (increase 200 > 0)
    let mut fam = build_borrow(S_P2PK, B_THRESH, ZERO32, ZERO32, 300, 200, 0, |_| Vec::new()).expect("threshold borrow builds");
    let report = meter(&mut fam.tx, fam.entries);
    println!("BORROW THRESH: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn borrow_below_threshold_rejected() {
    let mut guard = ZERO32;
    guard[0] = 250; // threshold 250 cents, increase only 200
    let err = expect_rejected(build_borrow(S_P2PK, B_THRESH, guard, guard, 300, 200, 0, |_| Vec::new()), "script ran, but verification failed");
    println!("below-threshold borrow rejected: {err}");
}

#[test]
fn borrow_value_decrease_rejected() {
    let err = expect_rejected(build_borrow(S_P2PK, B_THRESH, ZERO32, ZERO32, 300, 200, -50_000_000, |_| Vec::new()), "script ran, but verification failed");
    println!("borrow sompi decrease rejected: {err}");
}

#[test]
fn borrow_disabled_rejected() {
    let err = expect_rejected(build_borrow(S_P2PK, B_NONE, ZERO32, ZERO32, 300, 200, 0, |_| Vec::new()), "script ran, but verification failed");
    println!("borrow on disabled box rejected: {err}");
}

#[test]
fn borrow_schnorr_sig_receive_ok() {
    // guard = x-only pubkey of key 9; witness = sig65 by key 9 over the leader sighash
    let mut guard = ZERO32;
    guard.copy_from_slice(&xonly(9));
    let mut fam = build_borrow(S_P2PK, B_SIG, guard, guard, 300, 200, 0, |sig| sig()).expect("schnorr borrow builds");
    meter(&mut fam.tx, fam.entries);
}

#[test]
fn borrow_schnorr_wrong_key_rejected() {
    let mut guard = ZERO32;
    guard.copy_from_slice(&xonly(8)); // guard expects key 8; witness signs with key 9
    let err = expect_rejected(build_borrow(S_P2PK, B_SIG, guard, guard, 300, 200, 0, |sig| sig()), "script ran, but verification failed");
    println!("schnorr borrow wrong key rejected: {err}");
}

#[test]
fn borrow_hash_chain_receive_ok_and_guard_advances() {
    // guard_0 = blake3(next_guard || one_time_pk); witness = next_guard || pk || sig65
    let next_guard = [0x33u8; 32];
    let ot_pk = xonly(9);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&next_guard);
    preimage.extend_from_slice(&ot_pk);
    let guard0: [u8; 32] = blake3::hash(&preimage).into();
    let ot_pk_w = ot_pk.clone();
    let mut fam = build_borrow(S_P2PK, B_CHAIN, guard0, next_guard, 300, 200, 0, move |sig| {
        let mut w = Vec::with_capacity(129);
        w.extend_from_slice(&next_guard);
        w.extend_from_slice(&ot_pk_w);
        w.extend_from_slice(&sig());
        w
    })
    .expect("hash-chain borrow builds");
    meter(&mut fam.tx, fam.entries);
}

#[test]
fn borrow_hash_chain_stale_guard_rejected() {
    // continuation keeps the OLD guard instead of advancing to next_guard
    let next_guard = [0x33u8; 32];
    let ot_pk = xonly(9);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&next_guard);
    preimage.extend_from_slice(&ot_pk);
    let guard0: [u8; 32] = blake3::hash(&preimage).into();
    let ot_pk_w = ot_pk.clone();
    let err = expect_rejected(
        build_borrow(S_P2PK, B_CHAIN, guard0, guard0, 300, 200, 0, move |sig| {
            let mut w = Vec::with_capacity(129);
            w.extend_from_slice(&next_guard);
            w.extend_from_slice(&ot_pk_w);
            w.extend_from_slice(&sig());
            w
        }),
        "script ran, but verification failed",
    );
    println!("stale hash-chain guard rejected: {err}");
}

#[test]
fn borrow_on_authority_rejected() {
    // the authority marker must be unreachable via the borrow path even with
    // borrow-looking state
    let err = expect_rejected(build_borrow(S_AUTH, B_THRESH, ZERO32, ZERO32, 300, 200, 0, |_| Vec::new()), "script ran, but verification failed");
    println!("borrow on authority rejected: {err}");
}

// --- delegate custody ----------------------------------------------------------

#[test]
fn authority_delegate_rejected() {
    // an authority box (0x10) must not be spendable as a delegate under any leader
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes([0x42; 32]);
    let a = xonly(1);
    let gov = xonly(5);
    let leader_state = plain(700, &a);
    let auth_state = kusd_state(1_000_000, &gov, S_AUTH, B_NONE, &ZERO32);
    let out0 = plain(700 + 1_000_000, &a);
    let leader_utxo = builder.covenant_utxo("Kusd", leader_state.clone(), 200_000_000, 0, false, Some(covid)).expect("leader utxo");
    let auth_utxo = builder.covenant_utxo("Kusd", auth_state.clone(), DUST, 0, false, Some(covid)).expect("auth utxo");
    let (k1, k5) = (demo_keypair(1), demo_keypair(5));
    let new_states = ArtifactValue::Array(vec![obj(out0.clone())]);
    let context = TxContext::new()
        .actor_input(
            "Kusd",
            leader_state,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(new_states.clone()),
                    ArgValue::Value(ArtifactValue::Bytes(owner_witness_p2pk(tx, input_idx, &k1))),
                ]
            }),
            demo_outpoint(0x16, 0),
            leader_utxo.clone(),
            0,
        )
        .actor_input(
            "Kusd",
            auth_state,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(delegate_witness_p2pk(tx, input_idx, &k5)))]
            }),
            demo_outpoint(0x17, 0),
            auth_utxo.clone(),
            0,
        )
        .actor_output("Kusd", out0, CovenantBinding::new(0, covid), 200_000_000 + DUST);
    let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Family { tx, entries: vec![leader_utxo, auth_utxo] });
    let err = expect_rejected(result, "script ran, but verification failed");
    println!("authority delegate rejected: {err}");
}
