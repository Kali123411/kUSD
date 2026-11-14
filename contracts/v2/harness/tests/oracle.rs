// Oracle Stage 1: five operators, each signing its own price print offline
// (blake2b(oracle covid ‖ epoch ‖ price), verified with checkMsgSig); anyone
// relays three prints from distinct operators; the raw price is their median,
// accepted only when the three agree within 3%. Phase 5 rate limits, freeze
// and settle are unchanged.

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{
    Hash,
    tx::{CovenantBinding, ScriptPublicKey, UtxoEntry},
};
use kusd_v2_harness::{build_app, demo_keypair, demo_outpoint, member_digest, meter, meter_expect_err, print_digest, sign_digest};
use std::collections::BTreeMap;

const ORACLE_VALUE: u64 = 100_000_000;
const COVID: [u8; 32] = [0x07; 32];
const HOUR: i64 = 36_000;
const T0: i64 = 1_000_000;
const LIVE: i64 = 0;
const FROZEN: i64 = 1;
const SETTLED: i64 = 2;

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

#[derive(Clone, Debug)]
struct Ora {
    price: i64,
    mint: i64,
    liq: i64,
    epoch: i64,
    last: i64,
    status: i64,
    keys: [u8; 5], // operator key bytes (slot i's keypair = demo_keypair(keys[i]))
}

impl Ora {
    fn base(price: i64) -> Self {
        Ora { price, mint: price, liq: price, epoch: 9, last: T0, status: LIVE, keys: [10, 11, 12, 13, 14] }
    }
    fn map(&self) -> BTreeMap<String, ArtifactValue> {
        state! {
            price: self.price,
            mint_price: self.mint,
            liq_price: self.liq,
            epoch: self.epoch,
            last_update: self.last,
            status: self.status,
            m0: xonly(self.keys[0]),
            m1: xonly(self.keys[1]),
            m2: xonly(self.keys[2]),
            m3: xonly(self.keys[3]),
            m4: xonly(self.keys[4]),
        }
    }
}

fn median3(a: i64, b: i64, c: i64) -> i64 {
    let mut v = [a, b, c];
    v.sort();
    v[1]
}

/// The contract's rate-limit rule applied to the median, mirrored; `now` is the
/// median of the prints' signed-at times (review I-1/I-2: time comes from the
/// operators' signatures, not from the relayer's clock input).
fn after_refresh(prev: &Ora, p: i64, epoch: i64, now: i64) -> Ora {
    let elapsed = (now - prev.last).min(36_000);
    let mint = if p <= prev.mint { p } else { p.min(prev.mint + rate_step(prev.mint, elapsed, 360_000)) };
    let liq = if p >= prev.liq { p } else { p.max(prev.liq - rate_step(prev.liq, elapsed, 144_000)) };
    Ora { price: p, mint, liq, epoch, last: now, status: LIVE, keys: prev.keys }
}

fn clock_utxo(daa: i64) -> UtxoEntry {
    UtxoEntry::new(10_000_000, ScriptPublicKey::from_vec(0, vec![0x51]), daa as u64, false, None)
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

/// One relayed print: (operator index, price, signing key byte, epoch it was
/// signed for, covid it was signed for).
#[derive(Clone, Copy)]
struct Print {
    idx: i64,
    price: i64,
    key: u8,
    epoch: i64,
    covid: [u8; 32],
    t: i64, // DAA score the operator signed at; i64::MIN = "the refresh clock"
}

const AT_CLOCK: i64 = i64::MIN;

fn pr(prev: &Ora, idx: i64, price: i64, epoch: i64) -> Print {
    Print { idx, price, key: prev.keys[idx as usize], epoch, covid: COVID, t: AT_CLOCK }
}

fn build_refresh(prev: &Ora, prints: [Print; 3], epoch: i64, now: i64, out: Option<Ora>) -> Result<Built, String> {
    build_refresh_at(COVID, prev, prints, epoch, now, out)
}

fn build_refresh_at(oracle_covid: [u8; 32], prev: &Ora, prints: [Print; 3], epoch: i64, now: i64, out: Option<Ora>) -> Result<Built, String> {
    let artifact = build_app("oracle", "../ag/oracle.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(oracle_covid);
    let ts: Vec<i64> = prints.iter().map(|p| if p.t == AT_CLOCK { now } else { p.t }).collect();
    let med = median3(prints[0].price, prints[1].price, prints[2].price);
    let med_t = median3(ts[0], ts[1], ts[2]);
    let next = out.unwrap_or_else(|| after_refresh(prev, med, epoch, med_t));
    let utxo = builder.covenant_utxo("Oracle", prev.map(), ORACLE_VALUE, prev.last as u64, false, Some(covid)).expect("oracle utxo");
    let clock = clock_utxo(now);
    let mut args: Vec<ArtifactValue> = vec![ArtifactValue::Int(epoch)];
    for (k, p) in prints.iter().enumerate() {
        args.push(ArtifactValue::Int(p.idx));
        args.push(ArtifactValue::Int(p.price));
        args.push(ArtifactValue::Int(ts[k]));
        args.push(ArtifactValue::Bytes(sign_digest(&demo_keypair(p.key), print_digest(p.covid, p.epoch, p.price, ts[k]))));
    }
    args.push(ArtifactValue::Int(1));
    let context = TxContext::new()
        .actor_input(
            "Oracle",
            prev.map(),
            EntryCall::new("refresh").args_with(move |_tx, _idx| args.iter().cloned().map(ArgValue::Value).collect()),
            demo_outpoint(0x21, 0),
            utxo.clone(),
            0,
        )
        .input(demo_outpoint(0x2F, 0), clock.clone(), Vec::new(), 0)
        .actor_output("Oracle", next.map(), CovenantBinding::new(0, covid), ORACLE_VALUE);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo, clock] })
}

/// Rotation: slot -> new key, signed by three operators `signers` (none the
/// replaced slot) with keys `sign_keys`, for epoch `sign_epoch`.
fn build_set_member(prev: &Ora, slot: i64, new_key: u8, signers: [i64; 3], sign_keys: [u8; 3], sign_epoch: i64) -> Result<Built, String> {
    let artifact = build_app("oracle", "../ag/oracle.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(COVID);
    let mut next = prev.clone();
    next.keys[slot as usize] = new_key;
    next.epoch = prev.epoch + 1;
    let utxo = builder.covenant_utxo("Oracle", prev.map(), ORACLE_VALUE, prev.last as u64, false, Some(covid)).expect("oracle utxo");
    let digest = member_digest(COVID, sign_epoch, slot, &xonly(new_key));
    let mut args: Vec<ArtifactValue> = vec![ArtifactValue::Int(slot), ArtifactValue::Bytes(xonly(new_key))];
    for i in 0..3 {
        args.push(ArtifactValue::Int(signers[i]));
    }
    for i in 0..3 {
        args.push(ArtifactValue::Bytes(sign_digest(&demo_keypair(sign_keys[i]), digest)));
    }
    let context = TxContext::new()
        .actor_input(
            "Oracle",
            prev.map(),
            EntryCall::new("set_member").args_with(move |_tx, _idx| args.iter().cloned().map(ArgValue::Value).collect()),
            demo_outpoint(0x24, 0),
            utxo.clone(),
            0,
        )
        .actor_output("Oracle", next.map(), CovenantBinding::new(0, covid), ORACLE_VALUE);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

fn build_status(entry: &str, prev: &Ora, now: i64, new_status: i64) -> Result<Built, String> {
    let artifact = build_app("oracle", "../ag/oracle.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(COVID);
    let next = Ora { status: new_status, ..prev.clone() };
    let utxo = builder.covenant_utxo("Oracle", prev.map(), ORACLE_VALUE, prev.last as u64, false, Some(covid)).expect("oracle utxo");
    let clock = clock_utxo(now);
    let context = TxContext::new()
        .actor_input(
            "Oracle",
            prev.map(),
            EntryCall::new(entry).args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(1))]),
            demo_outpoint(0x23, 0),
            utxo.clone(),
            0,
        )
        .input(demo_outpoint(0x2E, 0), clock.clone(), Vec::new(), 0)
        .actor_output("Oracle", next.map(), CovenantBinding::new(0, covid), ORACLE_VALUE);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo, clock] })
}

fn build_peek(tampered_mint: Option<i64>) -> Result<Built, String> {
    let artifact = build_app("oracle", "../ag/oracle.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");
    let covid = Hash::from_bytes(COVID);
    let initial = Ora::base(4_000);
    let out = Ora { mint: tampered_mint.unwrap_or(initial.mint), ..initial.clone() };
    let utxo = builder.covenant_utxo("Oracle", initial.map(), ORACLE_VALUE, 0, false, Some(covid)).expect("oracle utxo");
    let context = TxContext::new()
        .actor_input("Oracle", initial.map(), "peek", demo_outpoint(0x22, 0), utxo.clone(), 0)
        .actor_output("Oracle", out.map(), CovenantBinding::new(0, covid), ORACLE_VALUE);
    let tx = builder.build(&context).map_err(|e| e.to_string())?;
    Ok(Built { tx, entries: vec![utxo] })
}

const VF: &str = "script ran, but verification failed";

// --- median of three independent prints ---------------------------------------

#[test]
fn refresh_median_of_three_prints_and_metered() {
    let o = Ora::base(4_000);
    let mut built = build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 2, 4_080, 10), pr(&o, 4, 4_040, 10)], 10, T0 + HOUR, None).expect("median refresh builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ORACLE refresh (median of 3 signed prints): units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn refresh_median_any_order() {
    let o = Ora::base(4_000);
    for (a, b, c) in [(4_000, 4_040, 4_080), (4_080, 4_000, 4_040), (4_040, 4_080, 4_000)] {
        let mut built = build_refresh(&o, [pr(&o, 1, a, 10), pr(&o, 2, b, 10), pr(&o, 3, c, 10)], 10, T0 + HOUR, None)
            .unwrap_or_else(|e| panic!("order ({a},{b},{c}) must build: {e}"));
        meter(&mut built.tx, built.entries);
    }
}

#[test]
fn refresh_claimed_non_median_rejected() {
    // the continuation must carry the MEDIAN, not the relayer's favourite print
    let o = Ora::base(4_000);
    let fav = after_refresh(&o, 4_080, 10, T0 + HOUR);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_040, 10), pr(&o, 2, 4_080, 10)], 10, T0 + HOUR, Some(fav)), VF);
    println!("non-median continuation rejected: {err}");
}

#[test]
fn refresh_wild_print_spread_rejected() {
    // one wild print among two honest ones: the set is refused (spread > 3%)
    let o = Ora::base(4_000);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_040, 10), pr(&o, 2, 8_000, 10)], 10, T0 + HOUR, None), VF);
    println!("wild print rejected: {err}");
}

#[test]
fn two_colluders_bounded_to_spread() {
    // two colluders + one honest (4000): within 3% of the median they get through...
    let o = Ora::base(4_000);
    let mut built = build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_110, 10), pr(&o, 2, 4_110, 10)], 10, T0 + HOUR, None).expect("in-band collusion builds");
    meter(&mut built.tx, built.entries);
    // ...but not beyond it
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_200, 10), pr(&o, 2, 4_200, 10)], 10, T0 + HOUR, None), VF);
    println!("out-of-band collusion rejected: {err}");
}

#[test]
fn refresh_duplicate_operator_rejected() {
    // one operator's print counted twice (indices must strictly increase)
    let o = Ora::base(4_000);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 1, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 10)], 10, T0 + HOUR, None), VF);
    println!("duplicate operator rejected: {err}");
}

#[test]
fn refresh_out_of_range_index_rejected() {
    let o = Ora::base(4_000);
    let p5 = Print { idx: 5, price: 4_000, key: 14, epoch: 10, covid: COVID, t: AT_CLOCK };
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), p5], 10, T0 + HOUR, None), VF);
    println!("index 5 rejected: {err}");
}

#[test]
fn refresh_non_member_print_rejected() {
    let o = Ora::base(4_000);
    let forged = Print { key: 33, ..pr(&o, 2, 4_000, 10) };
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), forged], 10, T0 + HOUR, None), VF);
    println!("non-member print rejected: {err}");
}

#[test]
fn print_for_another_epoch_rejected() {
    // an old print (signed for epoch 9) replayed into the epoch-10 refresh
    let o = Ora::base(4_000);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 9)], 10, T0 + HOUR, None), VF);
    println!("cross-epoch print rejected: {err}");
}

#[test]
fn print_for_another_oracle_rejected() {
    let o = Ora::base(4_000);
    let foreign = Print { covid: [0x08; 32], ..pr(&o, 2, 4_000, 10) };
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), foreign], 10, T0 + HOUR, None), VF);
    println!("cross-oracle print rejected: {err}");
}

#[test]
fn print_binding_follows_the_oracles_own_covid() {
    // the digest binds THIS oracle's covid dynamically: an oracle at a different
    // covid accepts prints signed for itself (and only those)
    let o = Ora::base(4_000);
    let other = [0x09u8; 32];
    let p = |idx: i64, price: i64| Print { covid: other, ..pr(&o, idx, price, 10) };
    let mut built = build_refresh_at(other, &o, [p(0, 4_000), p(1, 4_000), p(2, 4_000)], 10, T0 + HOUR, None).expect("prints for the other oracle build there");
    meter(&mut built.tx, built.entries);
    let err = expect_rejected(build_refresh_at(other, &o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 10)], 10, T0 + HOUR, None), VF);
    println!("prints for oracle 0x07 rejected by oracle 0x09: {err}");
}

#[test]
fn refresh_stale_epoch_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 9), pr(&o, 1, 4_000, 9), pr(&o, 2, 4_000, 9)], 9, T0 + HOUR, None), VF);
    println!("stale epoch rejected: {err}");
}

#[test]
fn refresh_epoch_jump_rejected() {
    let o = Ora::base(4_000);
    let e = 9 + 1_000_001;
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, e), pr(&o, 1, 4_000, e), pr(&o, 2, 4_000, e)], e, T0 + HOUR, None), VF);
    println!("epoch jump rejected: {err}");
}

// --- Phase 5 rate limits act on the median ----------------------------------------

#[test]
fn median_rise_still_rate_limited() {
    let o = Ora::base(4_000);
    let next = after_refresh(&o, 8_000, 10, T0 + HOUR);
    assert_eq!((next.mint, next.liq), (4_400, 8_000));
    let mut built = build_refresh(&o, [pr(&o, 0, 8_000, 10), pr(&o, 1, 8_000, 10), pr(&o, 2, 8_000, 10)], 10, T0 + HOUR, None).expect("rate-limited median builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn median_crash_after_silence_capped() {
    let o = Ora::base(4_000);
    let next = after_refresh(&o, 1, 10, T0 + 4 * HOUR);
    assert_eq!(next.liq, 3_000);
    let mut built = build_refresh(&o, [pr(&o, 0, 1, 10), pr(&o, 1, 1, 10), pr(&o, 2, 1, 10)], 10, T0 + 4 * HOUR, None).expect("capped crash builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn refresh_tiny_mint_price_not_stuck() {
    // final review I-1: at mint_price <= 9 the 10%/h step truncated to zero, so
    // one tiny print froze borrowing power forever; a refresh with elapsed time
    // now always lets it rise at least one unit
    let prev = Ora::base(5);
    let want = Ora { mint: 6, ..after_refresh(&prev, 100, 10, T0 + HOUR) };
    let prints = [pr(&prev, 0, 100, 10), pr(&prev, 1, 100, 10), pr(&prev, 2, 100, 10)];
    let mut built = build_refresh(&prev, prints, 10, T0 + HOUR, Some(want)).expect("tiny mint_price rises one unit");
    meter(&mut built.tx, built.entries);
}

#[test]
fn refresh_tiny_liq_price_not_stuck() {
    // mirror: at liq_price <= 3 the 25%/h fall truncated to zero
    let prev = Ora::base(3);
    let want = Ora { liq: 2, ..after_refresh(&prev, 1, 10, T0 + HOUR) };
    let prints = [pr(&prev, 0, 1, 10), pr(&prev, 1, 1, 10), pr(&prev, 2, 1, 10)];
    let mut built = build_refresh(&prev, prints, 10, T0 + HOUR, Some(want)).expect("tiny liq_price falls one unit");
    meter(&mut built.tx, built.entries);
}

#[test]
fn refresh_clock_before_last_update_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 10)], 10, T0 - 1, None), VF);
    println!("backwards clock rejected: {err}");
}

#[test]
fn refresh_after_settle_rejected() {
    let o = Ora { status: SETTLED, ..Ora::base(4_000) };
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 10)], 10, T0 + HOUR, None), VF);
    println!("refresh after settle rejected: {err}");
}

#[test]
fn refresh_unfreezes() {
    let o = Ora { status: FROZEN, ..Ora::base(4_000) };
    let mut built = build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), pr(&o, 2, 4_000, 10)], 10, T0 + 2 * HOUR, None).expect("unfreeze builds");
    meter(&mut built.tx, built.entries);
}

// --- operator rotation (3 signers, never the replaced slot) -------------------------

#[test]
fn set_member_3_signers_ok_and_metered() {
    let o = Ora::base(4_000);
    let mut built = build_set_member(&o, 2, 22, [0, 1, 3], [10, 11, 13], 9).expect("rotation builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ORACLE set_member: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn set_member_replaces_two_compromised_keys() {
    // review I-3: slots 3 and 4 are compromised and won't sign their own removal;
    // the three honest operators can still replace them (under 4-of-5 they couldn't)
    let o = Ora::base(4_000);
    let mut built = build_set_member(&o, 4, 24, [0, 1, 2], [10, 11, 12], 9).expect("honest three rotate slot 4");
    meter(&mut built.tx, built.entries);
}

#[test]
fn set_member_replaced_slot_cannot_sign() {
    // the slot being replaced can't count toward its own replacement
    let o = Ora::base(4_000);
    let err = expect_rejected(build_set_member(&o, 1, 22, [0, 1, 3], [10, 11, 13], 9), VF);
    println!("self-signed rotation rejected: {err}");
}

#[test]
fn set_member_bad_signature_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_set_member(&o, 2, 22, [0, 1, 3], [10, 11, 33], 9), VF);
    println!("forged rotation signature rejected: {err}");
}

#[test]
fn set_member_replayed_rotation_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_set_member(&o, 2, 22, [0, 1, 3], [10, 11, 13], 8), VF);
    println!("replayed rotation rejected: {err}");
}

#[test]
fn set_member_duplicate_key_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_set_member(&o, 2, 10, [0, 1, 3], [10, 11, 13], 9), VF);
    println!("duplicate-key rotation rejected: {err}");
}

#[test]
fn set_member_duplicate_signer_rejected() {
    let o = Ora::base(4_000);
    let err = expect_rejected(build_set_member(&o, 2, 22, [0, 0, 3], [10, 10, 13], 9), VF);
    println!("duplicate signer rejected: {err}");
}

#[test]
fn rotated_out_key_can_no_longer_print() {
    // after slot 4 is rotated 14 -> 24, a print signed by the retired key is
    // refused; the new key's print is accepted
    let rotated = Ora { keys: [10, 11, 12, 13, 24], epoch: 10, ..Ora::base(4_000) };
    let retired = Print { key: 14, ..pr(&rotated, 4, 4_000, 11) };
    let err = expect_rejected(build_refresh(&rotated, [pr(&rotated, 1, 4_000, 11), pr(&rotated, 3, 4_000, 11), retired], 11, T0 + HOUR, None), VF);
    println!("retired operator key rejected: {err}");
    let mut built = build_refresh(&rotated, [pr(&rotated, 1, 4_000, 11), pr(&rotated, 3, 4_000, 11), pr(&rotated, 4, 4_000, 11)], 11, T0 + HOUR, None).expect("new key prints");
    meter(&mut built.tx, built.entries);
}

#[test]
fn set_member_on_settled_feed_rejected() {
    let o = Ora { status: SETTLED, ..Ora::base(4_000) };
    let err = expect_rejected(build_set_member(&o, 2, 22, [0, 1, 3], [10, 11, 13], 9), VF);
    println!("rotation on settled feed rejected: {err}");
}

// --- review I-1 / I-2: time comes from the operators' signed timestamps ----------

#[test]
fn held_prints_cannot_revive_frozen_feed() {
    // prints signed at T0+HOUR (before the feed went stale), held back, relayed
    // ten hours later after a freeze: refused — reviving needs prints signed
    // AFTER the silence
    let o = Ora { status: FROZEN, ..Ora::base(4_000) };
    let held = |idx: i64| Print { t: T0 + HOUR / 2, ..pr(&o, idx, 4_000, 10) };
    let err = expect_rejected(build_refresh(&o, [held(0), held(1), held(2)], 10, T0 + 10 * HOUR, None), VF);
    println!("held prints reviving a frozen feed rejected: {err}");
}

#[test]
fn fresh_prints_revive_frozen_feed() {
    let o = Ora { status: FROZEN, ..Ora::base(4_000) };
    let fresh = |idx: i64| Print { t: T0 + 10 * HOUR, ..pr(&o, idx, 4_000, 10) };
    let mut built = build_refresh(&o, [fresh(0), fresh(1), fresh(2)], 10, T0 + 10 * HOUR, None).expect("fresh prints revive");
    meter(&mut built.tx, built.entries);
}

#[test]
fn future_dated_print_rejected() {
    // an operator can't stamp its print beyond what the clock input proves
    let o = Ora::base(4_000);
    let future = Print { t: T0 + 5 * HOUR, ..pr(&o, 2, 4_000, 10) };
    let err = expect_rejected(build_refresh(&o, [pr(&o, 0, 4_000, 10), pr(&o, 1, 4_000, 10), future], 10, T0 + HOUR, None), VF);
    println!("future-dated print rejected: {err}");
}

#[test]
fn relayer_clock_no_longer_sets_the_rate() {
    // review I-2: honest crash prints signed an hour after last_update move
    // liq_price the full 25% even if the relayer uses a stale-looking clock
    // input — elapsed comes from the signed times, the clock only caps them
    let o = Ora::base(4_000);
    let p = |idx: i64| Print { t: T0 + HOUR, ..pr(&o, idx, 2_000, 10) };
    let next = after_refresh(&o, 2_000, 10, T0 + HOUR);
    assert_eq!(next.liq, 3_000);
    let mut built = build_refresh(&o, [p(0), p(1), p(2)], 10, T0 + HOUR + 30, None).expect("signed-time rate builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn prints_older_than_last_update_rejected() {
    let o = Ora::base(4_000);
    let old = |idx: i64| Print { t: T0 - 100, ..pr(&o, idx, 4_000, 10) };
    let err = expect_rejected(build_refresh(&o, [old(0), old(1), old(2)], 10, T0 + HOUR, None), VF);
    println!("prints older than last_update rejected: {err}");
}

#[test]
fn spread_one_unit_slack_at_tiny_prices() {
    // review M-2: at KAS < $0.0034 the 3% band is under one unit; one unit of
    // slack keeps honest prints usable
    let o = Ora::base(34);
    let mut built = build_refresh(&o, [pr(&o, 0, 33, 10), pr(&o, 1, 33, 10), pr(&o, 2, 34, 10)], 10, T0 + HOUR, None).expect("tiny-price prints build");
    meter(&mut built.tx, built.entries);
}

// --- freeze / settle / peek (unchanged) ----------------------------------------------

#[test]
fn freeze_after_stale_ok() {
    let mut built = build_status("freeze", &Ora::base(4_000), T0 + HOUR + 1, FROZEN).expect("freeze builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ORACLE freeze: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn freeze_too_early_rejected() {
    let err = expect_rejected(build_status("freeze", &Ora::base(4_000), T0 + HOUR, FROZEN), VF);
    println!("early freeze rejected: {err}");
}

#[test]
fn settle_after_30_days_ok() {
    let o = Ora { status: FROZEN, ..Ora::base(4_000) };
    let mut built = build_status("settle", &o, T0 + 720 * HOUR + 1, SETTLED).expect("settle builds");
    meter(&mut built.tx, built.entries);
}

#[test]
fn settle_too_early_rejected() {
    let o = Ora { status: FROZEN, ..Ora::base(4_000) };
    let err = expect_rejected(build_status("settle", &o, T0 + 720 * HOUR, SETTLED), VF);
    println!("early settle rejected: {err}");
}

#[test]
fn peek_preserves_state_and_value() {
    let mut built = build_peek(None).expect("peek builds");
    let report = meter(&mut built.tx, built.entries);
    println!("ORACLE peek: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
}

#[test]
fn peek_state_tamper_rejected() {
    let err = expect_rejected(build_peek(Some(1)), VF);
    println!("peek tamper rejected: {err}");
}

/// Per-refresh rate step, mirrored from oracle.ag: at least one unit once time has elapsed.
fn rate_step(p: i64, elapsed: i64, div: i64) -> i64 {
    let s = p * elapsed / div;
    if s < 1 && elapsed > 0 { 1 } else { s }
}
