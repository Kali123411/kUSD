// kUSD v2 harness: build Argent apps and meter covenant transactions against
// mainnet consensus limits. The metering loop mirrors
// argent_runtime::execute_transaction_with_covenants (which is also invoked as
// the canonical gate) but reports per-input script units and both masses.
//
// NOTE: only compute and transient mass are non-contextual and checked here.
// Storage mass (KIP-9) is contextual — covenant box values must stay >= the
// 100M-sompi convention (see contracts/v2/README.md).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use argent_runtime::{Artifact, covenant_engine_flags};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    mass::{ComputeBudget, MassCalculator, ScriptUnits},
    config::params::MAINNET_PARAMS,
    tx::{MutableTransaction, PopulatedTransaction, Transaction, TransactionId, TransactionOutpoint, UtxoEntry, VerifiableTransaction},
};
use kaspa_txscript::{EngineCtx, SigCacheKey, TxScriptEngine, caches::Cache, covenants::CovenantsContext};
use secp256k1::{Keypair, Secp256k1, SecretKey};

#[derive(Debug)]
pub struct MeterReport {
    pub per_input_units: Vec<u64>,
    pub compute_mass: u64,
    pub transient_mass: u64,
}

fn build_dir(name: &str) -> PathBuf {
    // contracts/v2/build/<name>, anchored to this crate so tests can run from anywhere.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("build").join(name)
}

// Tests run in parallel; argent builds write generated files, so each app is
// built exactly once per process and shared from a cache.
fn artifact_cache() -> &'static Mutex<HashMap<String, Arc<Artifact>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Artifact>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_build(name: &str, build: impl FnOnce() -> Artifact) -> Arc<Artifact> {
    let mut cache = artifact_cache().lock().expect("artifact cache lock");
    if let Some(found) = cache.get(name) {
        return Arc::clone(found);
    }
    let artifact = Arc::new(build());
    cache.insert(name.to_string(), Arc::clone(&artifact));
    artifact
}

pub fn build_app_inline(name: &str, source: &str) -> Arc<Artifact> {
    let (name_owned, source_owned) = (name.to_string(), source.to_string());
    cached_build(name, move || {
        argent::build_inline(&format!("{name_owned}.ag"), &source_owned, build_dir(&name_owned))
            .unwrap_or_else(|err| panic!("argent build of inline app '{name_owned}' failed: {err}"))
    })
}

pub fn build_app(name: &str, src_path: &str) -> Arc<Artifact> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(src_path);
    cached_build(name, move || {
        argent::build_file(&src, build_dir(name)).unwrap_or_else(|err| panic!("argent build of {} failed: {err}", src.display()))
    })
}

fn measure_units(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Vec<u64>, String> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(100);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("covenants context: {e}"))?;
    let mut units = Vec::with_capacity(tx.inputs.len());
    for input_idx in 0..tx.inputs.len() {
        let input = populated.tx.inputs[input_idx].clone();
        let utxo = populated.utxo(input_idx).expect("selected input utxo");
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            &input,
            input_idx,
            utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
            covenant_engine_flags(),
            ScriptUnits(u64::MAX),
        );
        vm.execute().map_err(|e| format!("input {input_idx}: {e}"))?;
        units.push(vm.used_script_units().0);
    }
    Ok(units)
}

fn meter_inner(tx: &mut Transaction, entries: Vec<UtxoEntry>) -> Result<MeterReport, String> {
    let per_input_units = measure_units(tx, &entries)?;
    for (input_idx, units) in per_input_units.iter().enumerate() {
        let budget = ComputeBudget::checked_covering_script_units(ScriptUnits(*units))
            .ok_or_else(|| format!("compute budget overflow on input {input_idx}"))?;
        tx.inputs[input_idx].compute_commit = budget.into();
    }
    // Canonical gate: version check, re-execution under committed budgets, and
    // the non-contextual (compute + transient) mass limits.
    argent_runtime::execute_transaction_with_covenants(tx, entries).map_err(|e| e.to_string())?;
    let masses = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS).calc_non_contextual_masses(tx);
    Ok(MeterReport { per_input_units, compute_mass: masses.compute_mass, transient_mass: masses.transient_mass })
}

/// Execute every input under the covenant engine, commit minimal compute
/// budgets, and enforce mainnet non-contextual mass limits. Panics on any
/// failure so tests read as plain asserts.
pub fn meter(tx: &mut Transaction, entries: Vec<UtxoEntry>) -> MeterReport {
    meter_inner(tx, entries).unwrap_or_else(|e| panic!("meter: {e}"))
}

/// Same as `meter`, but asserts the transaction FAILS and returns the error.
pub fn meter_expect_err(tx: &mut Transaction, entries: Vec<UtxoEntry>) -> String {
    match meter_inner(tx, entries) {
        Ok(report) => panic!("expected failure, but tx executed cleanly: {report:?}"),
        Err(e) => e,
    }
}

// --- vault app bundle (vault.ag imports kusd.ag + oracle.ag) ---

/// Compile ag/vault.ag as the VaultApp bundle (once per process).
pub fn vault_bundle() -> &'static argent::CompiledAppBundle {
    static BUNDLE: OnceLock<argent::CompiledAppBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ag/vault.ag");
        argent::build_file_app_bundle(&src, "VaultApp", build_dir("vault"))
            .unwrap_or_else(|err| panic!("argent build of {} failed: {err}", src.display()))
    })
}

/// Compile ag/psm.ag as the PsmApp bundle (once per process).
pub fn psm_bundle() -> &'static argent::CompiledAppBundle {
    static BUNDLE: OnceLock<argent::CompiledAppBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ag/psm.ag");
        argent::build_file_app_bundle(&src, "PsmApp", build_dir("psm"))
            .unwrap_or_else(|err| panic!("argent build of {} failed: {err}", src.display()))
    })
}

/// Compile ag/budget.ag as the BudgetApp bundle (once per process).
pub fn budget_bundle() -> &'static argent::CompiledAppBundle {
    static BUNDLE: OnceLock<argent::CompiledAppBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ag/budget.ag");
        argent::build_file_app_bundle(&src, "BudgetApp", build_dir("budget"))
            .unwrap_or_else(|err| panic!("argent build of {} failed: {err}", src.display()))
    })
}

/// USD cents worth of `sompi` at `price` (1e-4 USD/KAS) — mirrors oracle.ag.
pub fn usd_cents_of(sompi: i64, price: i64) -> i64 {
    (sompi / 100) * price / 100_000_000
}

/// Sompi worth `cents` at `price` (1e-4 USD/KAS), truncated to 1e-4 KAS — mirrors oracle.ag.
pub fn sompi_of(cents: i64, price: i64) -> i64 {
    (cents * 1_000_000 / price) * 10_000
}

/// A LIVE oracle state with mint == liq == raw `price` (committee keys 10/11/12).
pub fn oracle_state_v2(price: i64) -> std::collections::BTreeMap<String, argent_runtime::ArtifactValue> {
    oracle_state_full(price, price, price, 0, 0)
}

pub fn oracle_state_full(price: i64, mint: i64, liq: i64, last_update: i64, status: i64) -> std::collections::BTreeMap<String, argent_runtime::ArtifactValue> {
    let x = |b: u8| demo_keypair(b).x_only_public_key().0.serialize().to_vec();
    argent_runtime::state! {
        price: price,
        mint_price: mint,
        liq_price: liq,
        epoch: 9,
        last_update: last_update,
        status: status,
        m0: x(10),
        m1: x(11),
        m2: x(12),
        m3: x(13),
        m4: x(14),
    }
}

/// blake2b-256 (OpBlake2b) of `data`.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).to_state().update(data).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Digest an operator signs for a price print:
/// blake2b(oracle_covid ‖ i64le(epoch) ‖ i64le(price) ‖ i64le(signed_at_daa)).
pub fn print_digest(oracle_covid: [u8; 32], epoch: i64, price: i64, signed_at: i64) -> [u8; 32] {
    let mut pre = oracle_covid.to_vec();
    pre.extend_from_slice(&epoch.to_le_bytes());
    pre.extend_from_slice(&price.to_le_bytes());
    pre.extend_from_slice(&signed_at.to_le_bytes());
    blake2b_256(&pre)
}

/// Digest operators sign to rotate `slot` to `new_key`:
/// blake2b(oracle_covid ‖ "member" ‖ i64le(epoch) ‖ i64le(slot) ‖ new_key).
pub fn member_digest(oracle_covid: [u8; 32], epoch: i64, slot: i64, new_key: &[u8]) -> [u8; 32] {
    let mut pre = oracle_covid.to_vec();
    pre.extend_from_slice(b"member");
    pre.extend_from_slice(&epoch.to_le_bytes());
    pre.extend_from_slice(&slot.to_le_bytes());
    pre.extend_from_slice(new_key);
    blake2b_256(&pre)
}

/// 64-byte Schnorr data-signature over a 32-byte digest (checkMsgSig).
pub fn sign_digest(keypair: &Keypair, digest: [u8; 32]) -> Vec<u8> {
    keypair.sign_schnorr(secp256k1::Message::from_digest(digest)).as_ref().to_vec()
}

/// Budget state (governance keys 20/21/22).
pub fn budget_state(limit: i64, available: i64, last_refill: i64, kusd_id: [u8; 32]) -> std::collections::BTreeMap<String, argent_runtime::ArtifactValue> {
    let x = |b: u8| demo_keypair(b).x_only_public_key().0.serialize().to_vec();
    argent_runtime::state! {
        daily_limit: limit,
        available: available,
        last_refill: last_refill,
        kusd_id: kusd_id.to_vec(),
        g0: x(20),
        g1: x(21),
        g2: x(22),
    }
}

/// Sompi worth `cents` at `price`, rounded UP to 1e-4 KAS — mirrors oracle.ag
/// `sompi_of_ceil` (what a user pays INTO a reserve).
pub fn sompi_of_ceil(cents: i64, price: i64) -> i64 {
    ((cents * 1_000_000 + price - 1) / price) * 10_000
}

/// Token-bucket refill — mirrors budget.ag `budget_refill`.
pub fn budget_refill(limit: i64, available: i64, last_refill: i64, now: i64) -> i64 {
    let elapsed = (now - last_refill).min(864_000);
    (available + limit * elapsed / 864_000).min(limit)
}

/// Compile ag/surplus.ag as the SurplusApp bundle (once per process).
pub fn surplus_bundle() -> &'static argent::CompiledAppBundle {
    static BUNDLE: OnceLock<argent::CompiledAppBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ag/surplus.ag");
        argent::build_file_app_bundle(&src, "SurplusApp", build_dir("surplus"))
            .unwrap_or_else(|err| panic!("argent build of {} failed: {err}", src.display()))
    })
}

/// One runtime bundle carrying every protocol app. The app graphs of VaultApp
/// and PsmApp share KusdApp/OracleApp dependencies (identical deterministic
/// artifacts); duplicates are skipped by app name and the builder's
/// dependency-id validation guards against drift.
pub fn protocol_runtime() -> argent_runtime::ArtifactBundle<'static> {
    let vb = vault_bundle();
    let pb = psm_bundle();
    let sb = surplus_bundle();
    let bb = budget_bundle();
    let mut bundle = argent_runtime::ArtifactBundle::new(vb.primary()).expect("primary bundle");
    let mut seen: Vec<&str> = vec![&vb.primary().app];
    for (app, artifact) in vb.apps().chain(pb.apps()).chain(sb.apps()).chain(bb.apps()) {
        if seen.contains(&app) {
            continue;
        }
        seen.push(app);
        bundle = bundle.with_artifact(artifact).expect("bundle artifact");
    }
    bundle
}

/// The kusd emission gate config (Phase 2): extension_commitment =
/// blake3(vault_template || psm_template || oracle_covid || psm_covid || surplus_covid || budget_covid).
/// The per-gate template lens are the witness args of `Kusd::emission`.
pub struct GateSetup {
    pub ext: Vec<u8>,
    pub vault_template: Vec<u8>,
    pub psm_template: Vec<u8>,
    pub oracle_covid: Vec<u8>,
    pub psm_covid: Vec<u8>,
    pub surplus_covid: Vec<u8>,
    pub budget_covid: Vec<u8>,
    pub vault_prefix_len: i64,
    pub vault_suffix_len: i64,
    pub psm_prefix_len: i64,
    pub psm_suffix_len: i64,
}

/// Full template parts (prefix bytes, suffix bytes, template hash) for an
/// actor in a single artifact — the contract script is prefix ++ state ++ suffix.
pub fn actor_template_parts(artifact: &Artifact, actor: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let t = artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|t| t.actor == actor)
        .unwrap_or_else(|| panic!("artifact carries no template receipt for actor '{actor}'"));
    (t.actor_type_handle.template.prefix.to_vec(), t.actor_type_handle.template.suffix.to_vec(), t.actor_type_handle.template.hash.to_vec())
}

/// (handle template hash, prefix len, suffix len) for an actor anywhere in the bundle.
fn handle_template(bundle: &argent::CompiledAppBundle, actor: &str) -> Option<(Vec<u8>, i64, i64)> {
    bundle
        .apps()
        .flat_map(|(_, artifact)| artifact.argent.template_plan.templates.iter())
        .find(|t| t.actor == actor)
        .map(|t| {
            let template = &t.actor_type_handle.template;
            (template.hash.to_vec(), template.prefix.len() as i64, template.suffix.len() as i64)
        })
}

pub fn gate_setup(oracle_covid: [u8; 32], psm_covid: [u8; 32], surplus_covid: [u8; 32], budget_covid: [u8; 32]) -> GateSetup {
    let (vault_template, vault_prefix_len, vault_suffix_len) =
        handle_template(vault_bundle(), "Vault").expect("bundle carries the Vault template receipt");
    let (psm_template, psm_prefix_len, psm_suffix_len) =
        handle_template(psm_bundle(), "Psm").expect("bundle carries the Psm template receipt");
    let mut preimage = Vec::with_capacity(192);
    preimage.extend_from_slice(&vault_template);
    preimage.extend_from_slice(&psm_template);
    preimage.extend_from_slice(&oracle_covid);
    preimage.extend_from_slice(&psm_covid);
    preimage.extend_from_slice(&surplus_covid);
    preimage.extend_from_slice(&budget_covid);
    GateSetup {
        ext: blake3::hash(&preimage).as_bytes().to_vec(),
        vault_template,
        psm_template,
        oracle_covid: oracle_covid.to_vec(),
        psm_covid: psm_covid.to_vec(),
        surplus_covid: surplus_covid.to_vec(),
        budget_covid: budget_covid.to_vec(),
        vault_prefix_len,
        vault_suffix_len,
        psm_prefix_len,
        psm_suffix_len,
    }
}

// --- demo fixtures (copied from argent-playground src/lib.rs) ---

pub fn demo_outpoint(byte: u8, index: u32) -> TransactionOutpoint {
    TransactionOutpoint { transaction_id: TransactionId::from_bytes([byte; 32]), index }
}

pub fn demo_keypair(byte: u8) -> Keypair {
    let secret_key = SecretKey::from_slice(&[byte; 32]).expect("demo secret key is valid");
    Keypair::from_secret_key(&Secp256k1::new(), &secret_key)
}

/// KCC-20 leader witness for the normal path and an 0x00 (P2PK-Schnorr) owner:
/// `[PATH_NORMAL] ++ sig65` (65-byte schnorr sig incl. sighash-type byte).
pub fn owner_witness_p2pk<T: AsRef<Transaction>>(tx: &MutableTransaction<T>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
    let mut w = vec![0x00];
    w.extend_from_slice(&sign_input(tx, input_idx, keypair));
    w
}

/// KCC-20 borrow-path leader witness: `[PATH_BORROW] ++ path_witness`.
pub fn borrow_witness(path_witness: Vec<u8>) -> Vec<u8> {
    let mut w = vec![0x01];
    w.extend_from_slice(&path_witness);
    w
}

/// Delegate witness (transfer_delegator) for an 0x00 owner: bare sig65 against
/// the DELEGATE's own input sighash.
pub fn delegate_witness_p2pk<T: AsRef<Transaction>>(tx: &MutableTransaction<T>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
    sign_input(tx, input_idx, keypair)
}

pub fn sign_input<T: AsRef<Transaction>>(tx: &MutableTransaction<T>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused_values);
    let message = secp256k1::Message::from_digest(sig_hash.as_bytes());
    let signature = keypair.sign_schnorr(message);
    let mut encoded = signature.as_ref().to_vec();
    encoded.push(SIG_HASH_ALL.to_u8());
    encoded
}

/// How a test transaction co-spends the global mint budget.
#[derive(Clone, Debug)]
pub enum BudgetUse {
    /// issuance of `d` cents to `recipient` (vault mint / psm swap_in[_fee])
    Meter { d: i64, recipient: Vec<u8> },
    /// refund of `r` burned cents (vault repay / liquidate, psm swap_out[_fee])
    Credit { r: i64 },
}

/// Append the budget box as input `idx` (its own DAA score 0 is the clock;
/// last_refill 0, so no refill accrues) and its pinned continuation.
pub fn add_budget<'a>(
    context: argent_runtime::TxContext<'a>,
    builder: &argent_runtime::TxBuilder<'_>,
    use_: BudgetUse,
    idx: u16,
    budget_covid: [u8; 32],
    kusd_covid: [u8; 32],
    limit: i64,
    available: i64,
) -> (argent_runtime::TxContext<'a>, UtxoEntry) {
    use argent_runtime::{ArgValue, ArtifactValue, EntryCall};
    let covid = kaspa_consensus_core::Hash::from_bytes(budget_covid);
    let b_in = budget_state(limit, available, 0, kusd_covid);
    let (after, call) = match use_ {
        BudgetUse::Meter { d, recipient } => {
            let i = idx as i64;
            (available - d, EntryCall::new("meter").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(d)), ArgValue::Value(ArtifactValue::Int(i)), ArgValue::Value(ArtifactValue::Bytes(recipient.clone()))]
            }))
        }
        BudgetUse::Credit { r } => {
            let i = idx as i64;
            ((available + r).min(limit), EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(r)), ArgValue::Value(ArtifactValue::Int(i))]))
        }
    };
    let b_out = budget_state(limit, after, 0, kusd_covid);
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), 100_000_000, 0, false, Some(covid)).expect("budget utxo");
    let context = context
        .actor_input("budget_app::Budget", b_in, call, demo_outpoint(0xBB, idx as u32), utxo.clone(), 0)
        .actor_output("budget_app::Budget", b_out, kaspa_consensus_core::tx::CovenantBinding::new(idx, covid), 100_000_000);
    (context, utxo)
}
