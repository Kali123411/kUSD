// kUSD v2 TN10 deploy driver — stage-driven, env-controlled.
//
//   STAGE=status|oracle|psm|authority|wire|vault|mint|swapin|swapout \
//     cargo run --release --bin tn10_deploy
//
// Keys are FRESH TN10-only keys generated into ~/.kusd-v2-tn10/ (0600) on
// first run — never the owner's mainnet keys, never committed. Progress
// (covids, outpoints, box states) persists in ~/.kusd-v2-tn10/state.json.
// Every tx is locally pre-verified under the node-equivalent covenant engine
// (meter) before broadcast; DRY_RUN=1 stops before submission.
// Genesis order and rationale: contracts/v2/deploy/README.md.

use std::collections::BTreeMap;
use std::path::PathBuf;

use argent_runtime::{ArgValue, ArtifactValue, CovenantOutput, EntryCall, InputSigScript, TxBuilder, TxContext, state};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    Hash,
    hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
    hashing::sighash_type::SIG_HASH_ALL,
    tx::{Transaction, TransactionOutpoint, UtxoEntry},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_notify::subscription::context::SubscriptionContext;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_txscript::pay_to_address_script;
use kusd_v2_harness::{gate_setup, meter, protocol_runtime, sign_input};
use secp256k1::{Keypair, Secp256k1, SecretKey};

// point KUSD_TN10_RPC at your synced TN10 node (gRPC)
fn rpc_url() -> String {
    std::env::var("KUSD_TN10_RPC").unwrap_or_else(|_| "grpc://127.0.0.1:16210".into())
}
const DUST: u64 = 100_000_000;
const TOMBSTONE: u64 = 100_000_000;
const FEE: u64 = 10_000_000; // node standardness: fee >= ~100 sompi per transient-mass unit

const ORACLE_PRICE: i64 = 4_000; // 1e-4 USD per KAS at genesis ($0.40)
const AUTH_SUPPLY: i64 = 100_000_000; // $1M un-issued
const PSM_CEILING: i64 = 100_000; // $1,000
const VAULT_COLLATERAL: i64 = 1_000_000_000; // 10 KAS
const MINT_D: i64 = 200; // $2.00
const SWAP_C: i64 = 400; // $4.00
const BUDGET_LIMIT: i64 = 5_000_000; // $50,000/day global issuance (KSD figure)

// --- keys & state -----------------------------------------------------------

fn keydir() -> PathBuf {
    let dir = PathBuf::from(std::env::var("HOME").expect("HOME")).join(".kusd-v2-tn10");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).expect("create keydir");
        let _ = std::process::Command::new("chmod").args(["700"]).arg(&dir).status();
    }
    dir
}

fn keypair(name: &str) -> Keypair {
    let path = keydir().join(format!("{name}.key"));
    let secp = Secp256k1::new();
    if path.exists() {
        let hex = std::fs::read_to_string(&path).expect("read key");
        let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).expect("hex")).collect();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&bytes).expect("seckey"))
    } else {
        let mut bytes = [0u8; 32];
        use std::io::Read;
        std::fs::File::open("/dev/urandom").expect("urandom").read_exact(&mut bytes).expect("entropy");
        let sk = SecretKey::from_slice(&bytes).expect("fresh seckey");
        std::fs::write(&path, hex32(&bytes)).expect("write key");
        let _ = std::process::Command::new("chmod").args(["600"]).arg(&path).status();
        println!("generated fresh TN10 key: {}", path.display());
        Keypair::from_secret_key(&secp, &sk)
    }
}

fn hex32(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn xonly(kp: &Keypair) -> Vec<u8> {
    kp.x_only_public_key().0.serialize().to_vec()
}

fn address(kp: &Keypair) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &kp.x_only_public_key().0.serialize())
}

fn state_path() -> PathBuf {
    keydir().join("state.json")
}

fn load_state() -> serde_json::Value {
    std::fs::read_to_string(state_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| serde_json::json!({}))
}

fn save_state(v: &serde_json::Value) {
    std::fs::write(state_path(), serde_json::to_string_pretty(v).expect("state json")).expect("write state");
}

fn record_box(name: &str, covid: Hash, txid: Hash, index: u32, value: u64, extra: serde_json::Value) {
    let mut st = load_state();
    st[name] = serde_json::json!({
        "covid": covid.to_string(), "txid": txid.to_string(), "index": index, "value": value, "extra": extra,
    });
    save_state(&st);
    println!("state.json <- {name}: covid={covid} outpoint={txid}:{index} value={value}");
}

fn box_info(name: &str) -> (Hash, TransactionOutpoint, u64, serde_json::Value) {
    let st = load_state();
    let b = &st[name];
    assert!(!b.is_null(), "state.json has no '{name}' — run its stage first");
    let covid: Hash = b["covid"].as_str().unwrap().parse().expect("covid");
    let txid: Hash = b["txid"].as_str().unwrap().parse().expect("txid");
    let index = b["index"].as_u64().unwrap() as u32;
    let value = b["value"].as_u64().unwrap();
    (covid, TransactionOutpoint::new(txid, index), value, b["extra"].clone())
}

// --- covenant state maps (mirror the test builders) -------------------------

fn oracle_map(price: i64, mint: i64, liq: i64, epoch: i64, last: i64, status: i64) -> BTreeMap<String, ArtifactValue> {
    let k = |i: usize| xonly(&keypair(&operator_name(i)));
    state! {
        price: price,
        mint_price: mint,
        liq_price: liq,
        epoch: epoch,
        last_update: last,
        status: status,
        m0: k(0),
        m1: k(1),
        m2: k(2),
        m3: k(3),
        m4: k(4),
    }
}

/// Key name currently holding operator slot `i` (rotations recorded in state.json).
fn operator_name(i: usize) -> String {
    let st = load_state();
    st.get("operators").and_then(|o| o.get(i)).and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| format!("oracle{i}"))
}

/// The oracle state recorded in state.json extras {price, mint, liq, epoch, last, status}.
fn oracle_map_from(e: &serde_json::Value) -> BTreeMap<String, ArtifactValue> {
    let g = |k: &str| e[k].as_i64().unwrap_or_else(|| panic!("oracle extra '{k}' missing"));
    oracle_map(g("price"), g("mint"), g("liq"), g("epoch"), g("last"), g("status"))
}

fn oracle_extra_json(price: i64, mint: i64, liq: i64, epoch: i64, last: i64, status: i64) -> serde_json::Value {
    serde_json::json!({"price": price, "mint": mint, "liq": liq, "epoch": epoch, "last": last, "status": status})
}

fn budget_map(limit: i64, available: i64, last: i64, kusd_id: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    let (g0, g1, g2) = (keypair("gov0"), keypair("gov1"), keypair("gov2"));
    state! { daily_limit: limit, available: available, last_refill: last, kusd_id: kusd_id, g0: xonly(&g0), g1: xonly(&g1), g2: xonly(&g2) }
}

/// Covid of the live budget box (zeros before its genesis).
fn budget_id_bytes() -> Vec<u8> {
    let st = load_state();
    if st.get("budget").is_some() {
        box_info("budget").0.as_bytes().to_vec()
    } else {
        vec![0u8; 32]
    }
}

fn psm_state_map(ceiling: i64, minted: i64, spread: i64, kusd_id: Vec<u8>, oracle_id: Vec<u8>, surplus_id: Vec<u8>, budget_id: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    let (g0, g1, g2) = (keypair("gov0"), keypair("gov1"), keypair("gov2"));
    state! { ceiling_cents: ceiling, minted_cents: minted, spread_bps: spread, g0: xonly(&g0), g1: xonly(&g1), g2: xonly(&g2), kusd_id: kusd_id, oracle_id: oracle_id, surplus_id: surplus_id, budget_id: budget_id }
}

fn surplus_state_map(kusd_id: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    let (g0, g1, g2) = (keypair("gov0"), keypair("gov1"), keypair("gov2"));
    state! { g0: xonly(&g0), g1: xonly(&g1), g2: xonly(&g2), kusd_id: kusd_id }
}

fn kusd_state_map(amount: i64, owner: Vec<u8>, scheme: u8, ext: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    state! { amount: amount, owner: owner, owner_scheme: scheme, borrow_scheme: 0u8, borrow_guard: vec![0u8; 32], extension_commitment: ext }
}

fn kusd_state_map_borrow(amount: i64, owner: Vec<u8>, borrow: u8, guard: Vec<u8>, ext: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    state! { amount: amount, owner: owner, owner_scheme: 0x00u8, borrow_scheme: borrow, borrow_guard: guard, extension_commitment: ext }
}

fn vault_state_map(collateral: i64, debt: i64, kusd_id: Vec<u8>, oracle_id: Vec<u8>, surplus_id: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    state! { owner: xonly(&keypair("deploy")), collateral: collateral, debt: debt, kusd_id: kusd_id, oracle_id: oracle_id, surplus_id: surplus_id, budget_id: budget_id_bytes() }
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

fn live_gate() -> kusd_v2_harness::GateSetup {
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (psm_covid, _, _, _) = box_info("psm");
    let (surplus_covid, _, _, _) = box_info("surplus");
    let (budget_covid, _, _, _) = box_info("budget");
    gate_setup(oracle_covid.as_bytes(), psm_covid.as_bytes(), surplus_covid.as_bytes(), budget_covid.as_bytes())
}

fn emission_args(states: ArtifactValue, gate_idx: i64, psm_gate: bool) -> Vec<ArgValue> {
    let gate = live_gate();
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

// --- rpc --------------------------------------------------------------------

async fn rpc() -> GrpcClient {
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        rpc_url(),
        Some(SubscriptionContext::new()),
        true,
        None,
        false,
        Default::default(),
        Default::default(),
    )
    .await
    .expect("connect to TN10 node (is kaspad running with --utxoindex?)")
}

/// Largest spendable P2PK utxo at the deploy address with value >= min.
async fn pick_funding(client: &GrpcClient, min: u64) -> (TransactionOutpoint, UtxoEntry) {
    let addr = address(&keypair("deploy"));
    let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("get_utxos_by_addresses");
    let mut best: Option<(u64, TransactionOutpoint, UtxoEntry)> = None;
    for u in utxos {
        let amount = u.utxo_entry.amount;
        if amount < min {
            continue;
        }
        let outpoint = TransactionOutpoint::new(u.outpoint.transaction_id, u.outpoint.index);
        let entry = UtxoEntry::new(amount, u.utxo_entry.script_public_key.clone(), u.utxo_entry.block_daa_score, u.utxo_entry.is_coinbase, None);
        if best.as_ref().map(|(v, _, _)| amount > *v).unwrap_or(true) {
            best = Some((amount, outpoint, entry));
        }
    }
    let (v, o, e) = best.unwrap_or_else(|| panic!("no spendable utxo >= {min} sompi at {addr} — fund the deploy address"));
    println!("funding: {}:{} ({} sompi)", o.transaction_id, o.index, v);
    (o, e)
}

fn p2pk_signer<'a>(kp: Keypair) -> InputSigScript<'a> {
    InputSigScript::with_transaction(move |tx, input_idx| {
        let reused = SigHashReusedValuesUnsync::new();
        let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
        let msg = secp256k1::Message::from_digest(hash.as_bytes());
        let mut sig = kp.sign_schnorr(msg).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8()); // 65 bytes total
        let mut script = vec![0x41]; // OP_DATA_65
        script.extend_from_slice(&sig);
        script
    })
}

async fn preverify_and_submit(label: &str, tx: &mut Transaction, entries: Vec<UtxoEntry>, client: &GrpcClient) -> Hash {
    let report = meter(tx, entries);
    println!("{label}: pre-verify OK — units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
    if std::env::var("DRY_RUN").is_ok() {
        println!("{label}: DRY_RUN — not submitting");
        std::process::exit(0);
    }
    tx.finalize(); // AFTER bindings+sigscripts — txid is cached at construction; finalize after mutating
    let txid = tx.id();
    println!("{label}: submitting {txid} ...");
    client.submit_transaction((&*tx).into(), false).await.expect("submit");
    println!("{label}: ACCEPTED {txid}");
    archive_evidence(label, txid, tx);
    txid
}

/// Append every accepted tx to the pitch evidence archive (JSON of the full
/// RPC transaction + an INDEX.md row) so cited txids survive TN10 resets.
fn archive_evidence(label: &str, txid: Hash, tx: &Transaction) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/pitch/evidence");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let rpc_tx: kaspa_rpc_core::RpcTransaction = tx.into();
    let fname = format!("{}-{}.json", label.to_lowercase().replace([' ', '_'], "-"), txid);
    if let Ok(body) = serde_json::to_string_pretty(&rpc_tx) {
        let _ = std::fs::write(dir.join(&fname), body);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let row = format!("| {label} | `{txid}` | [{fname}]({fname}) | {now} |\n");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("INDEX.md")) {
            let _ = f.write_all(row.as_bytes());
        }
    }
}

// --- stages -----------------------------------------------------------------

/// Emit the oracle bootstrap JSON for `argentc genesis compose` from the REAL
/// keys and the funding outpoint recorded by the live oracle genesis.
/// Env: BOOT_TXID = the authorizing (funding) outpoint txid, BOOT_INDEX (default 0).
fn oracle_bootstrap_json() {
    let txid = std::env::var("BOOT_TXID").expect("BOOT_TXID (funding outpoint txid)");
    let index: u32 = std::env::var("BOOT_INDEX").map(|s| s.parse().unwrap()).unwrap_or(0);
    let int = |v: i64| serde_json::json!({"kind": "int", "value": v});
    let bytes = |v: Vec<u8>| serde_json::json!({"kind": "bytes", "value": v});
    let boot = serde_json::json!({
        "app": "OracleApp",
        "authorizing_outpoint": {"transactionId": txid, "index": index},
        "outputs": [{
            "index": 0,
            "value": DUST,
            "actor": "Oracle",
            "authored_state": {
                "price": int(ORACLE_PRICE),
                "mint_price": int(ORACLE_PRICE),
                "liq_price": int(ORACLE_PRICE),
                "epoch": int(1),
                "last_update": int(std::env::var("BOOT_LAST").map(|s| s.parse().unwrap()).unwrap_or(0)),
                "status": int(0),
                "m0": bytes(xonly(&keypair("oracle0"))),
                "m1": bytes(xonly(&keypair("oracle1"))),
                "m2": bytes(xonly(&keypair("oracle2"))),
                "m3": bytes(xonly(&keypair("oracle3"))),
                "m4": bytes(xonly(&keypair("oracle4"))),
            }
        }]
    });
    println!("{}", serde_json::to_string_pretty(&boot).unwrap());
}

/// Same, for the unwired PSM genesis (kusd_id = zeros, oracle_id from state.json).
fn psm_bootstrap_json() {
    let txid = std::env::var("BOOT_TXID").expect("BOOT_TXID (funding outpoint txid)");
    let index: u32 = std::env::var("BOOT_INDEX").map(|s| s.parse().unwrap()).unwrap_or(0);
    let (oracle_covid, _, _, _) = box_info("oracle");
    let int = |v: i64| serde_json::json!({"kind": "int", "value": v});
    let bytes = |v: Vec<u8>| serde_json::json!({"kind": "bytes", "value": v});
    let boot = serde_json::json!({
        "app": "PsmApp",
        "authorizing_outpoint": {"transactionId": txid, "index": index},
        "outputs": [{
            "index": 0,
            "value": TOMBSTONE,
            "actor": "Psm",
            "authored_state": {
                "ceiling_cents": int(PSM_CEILING),
                "minted_cents": int(0),
                "spread_bps": int(0),
                "g0": bytes(xonly(&keypair("gov0"))),
                "g1": bytes(xonly(&keypair("gov1"))),
                "g2": bytes(xonly(&keypair("gov2"))),
                "kusd_id": bytes(vec![0u8; 32]),
                "oracle_id": bytes(oracle_covid.as_bytes().to_vec()),
                "surplus_id": bytes(vec![0u8; 32]),
                "budget_id": bytes(vec![0u8; 32]),
            }
        }]
    });
    println!("{}", serde_json::to_string_pretty(&boot).unwrap());
}

/// Same, for the authority genesis (ext from live_gate()).
fn kusd_bootstrap_json() {
    let txid = std::env::var("BOOT_TXID").expect("BOOT_TXID (funding outpoint txid)");
    let index: u32 = std::env::var("BOOT_INDEX").map(|s| s.parse().unwrap()).unwrap_or(0);
    let gate = live_gate();
    let int = |v: i64| serde_json::json!({"kind": "int", "value": v});
    let bytes = |v: Vec<u8>| serde_json::json!({"kind": "bytes", "value": v});
    let boot = serde_json::json!({
        "app": "KusdApp",
        "authorizing_outpoint": {"transactionId": txid, "index": index},
        "outputs": [{
            "index": 0,
            "value": DUST,
            "actor": "Kusd",
            "authored_state": {
                "amount": int(AUTH_SUPPLY),
                "owner": bytes(xonly(&keypair("gov0"))),
                "owner_scheme": serde_json::json!({"kind": "byte", "value": 0x10}),
                "borrow_scheme": serde_json::json!({"kind": "byte", "value": 0}),
                "borrow_guard": bytes(vec![0u8; 32]),
                "extension_commitment": bytes(gate.ext.clone()),
            }
        }]
    });
    println!("{}", serde_json::to_string_pretty(&boot).unwrap());
}

async fn status(client: &GrpcClient) {
    let info = client.get_server_info().await.expect("get_server_info");
    println!("node: synced={} virtual_daa={}", info.is_synced, info.virtual_daa_score);
    let addr = address(&keypair("deploy"));
    println!("deploy address: {addr}");
    let utxos = client.get_utxos_by_addresses(vec![addr]).await.expect("utxos");
    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    println!("deploy balance: {} sompi across {} utxos", total, utxos.len());
    println!("state.json: {}", serde_json::to_string_pretty(&load_state()).unwrap());
}

async fn oracle_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let need = DUST + FEE + DUST; // box + fee + change floor
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - DUST - FEE;
    let last = funding.block_daa_score as i64;
    let keys: Vec<Vec<u8>> = (0..5).map(|i| xonly(&keypair(&operator_name(i)))).collect();
    for a in 0..5 {
        for b in (a + 1)..5 {
            assert_ne!(keys[a], keys[b], "operator slots {a} and {b} share a key — one operator would vote twice");
        }
    }
    let st = oracle_map(ORACLE_PRICE, ORACLE_PRICE, ORACLE_PRICE, 1, last, 0);
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::oracle", "oracle_app::Oracle", st, DUST)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("oracle genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("ORACLE-GENESIS", &mut tx, vec![funding], client).await;
    record_box("oracle", root.covenant_id, txid, 0, DUST, oracle_extra_json(ORACLE_PRICE, ORACLE_PRICE, ORACLE_PRICE, 1, last, 0));
}

async fn psm_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, _, _, _) = box_info("oracle");
    let need = TOMBSTONE + FEE + DUST;
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - TOMBSTONE - FEE;
    let st = psm_state_map(PSM_CEILING, 0, 0, vec![0u8; 32], oracle_covid.as_bytes().to_vec(), vec![0u8; 32], vec![0u8; 32]);
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::psm", "psm_app::Psm", st, TOMBSTONE)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("psm genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("PSM-GENESIS", &mut tx, vec![funding], client).await;
    record_box("psm", root.covenant_id, txid, 0, TOMBSTONE, serde_json::json!({"ceiling": PSM_CEILING, "minted": 0, "wired": false}));
}

async fn authority_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let need = DUST + FEE + DUST;
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - DUST - FEE;
    let st = kusd_state_map(AUTH_SUPPLY, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::kusd", "kusd_app::Kusd", st, DUST)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("authority genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("AUTHORITY-GENESIS", &mut tx, vec![funding], client).await;
    record_box("authority", root.covenant_id, txid, 0, DUST, serde_json::json!({"amount": AUTH_SUPPLY, "ext": hex32(&gate.ext)}));
}

async fn wire(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (psm_covid, psm_outpoint, psm_value, _) = box_info("psm");
    let (kusd_covid, _, _, _) = box_info("authority");
    let (surplus_covid, _, _, _) = box_info("surplus");

    let psm_in = psm_state_map(PSM_CEILING, 0, 0, vec![0u8; 32], oracle_covid.as_bytes().to_vec(), vec![0u8; 32], vec![0u8; 32]);
    let psm_out = psm_state_map(PSM_CEILING, 0, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid.as_bytes().to_vec(), budget_id_bytes());
    let psm_utxo = builder
        .covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid))
        .expect("psm utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let (ga, gb) = (keypair("gov0"), keypair("gov2"));
    let kusd_arg = kusd_covid.as_bytes().to_vec();
    let surplus_arg = surplus_covid.as_bytes().to_vec();
    let budget_arg = budget_id_bytes();
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("wire").args_with(move |tx, input_idx| {
                let reused = SigHashReusedValuesUnsync::new();
                let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
                let msg = secp256k1::Message::from_digest(hash.as_bytes());
                let sig = |kp: &Keypair| {
                    let mut s = kp.sign_schnorr(msg).as_ref().to_vec();
                    s.push(SIG_HASH_ALL.to_u8());
                    s
                };
                vec![
                    ArgValue::Value(ArtifactValue::Bytes(kusd_arg.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(surplus_arg.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(budget_arg.clone())),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sig(&ga))),
                    ArgValue::Value(ArtifactValue::Bytes(sig(&gb))),
                ]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("psm_app::Psm", psm_out, kaspa_consensus_core::tx::CovenantBinding::new(0, psm_covid), psm_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("wire tx");
    let txid = preverify_and_submit("WIRE", &mut tx, vec![psm_utxo, funding], client).await;
    record_box("psm", psm_covid, txid, 0, psm_value, serde_json::json!({"ceiling": PSM_CEILING, "minted": 0, "wired": true}));
}

async fn vault_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (kusd_covid, _, _, _) = box_info("authority");
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let vault_value = TOMBSTONE + VAULT_COLLATERAL as u64 + 300_000_000; // surplus funds emitted dust + fees
    let need = vault_value + FEE + DUST;
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - vault_value - FEE;
    let st = vault_state_map(VAULT_COLLATERAL, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::vault", "vault_app::Vault", st, vault_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("vault genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("VAULT-GENESIS", &mut tx, vec![funding], client).await;
    record_box(&env_name("VAULT_BOX", "vault"), root.covenant_id, txid, 0, vault_value, serde_json::json!({"collateral": VAULT_COLLATERAL, "debt": 0}));
}

async fn mint(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let vault_name = env_name("VAULT_BOX", "vault");
    let minted_name = env_name("MINTED_BOX", "minted");
    let (vault_covid, vault_outpoint, vault_value, vault_extra) = box_info(&vault_name);
    let (surplus_covid_h, _, _, _) = box_info("surplus");

    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let collateral = vault_extra["collateral"].as_i64().unwrap();
    let debt = vault_extra["debt"].as_i64().unwrap();

    let deploy = keypair("deploy");
    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount - MINT_D, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let emitted = kusd_state_map(MINT_D, xonly(&deploy), 0x00, gate.ext.clone());
    let vault_in = vault_state_map(collateral, debt, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_out = vault_state_map(collateral, debt + MINT_D, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());

    let vault_value_out = vault_value - DUST - FEE; // surplus pays the emitted box + fee

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");
    // clock = the funding input (real confirmation DAA from the node), input 4
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    let (b_in, b_out, b_utxo, b_covid, b_outpoint, b_value, b_extra) = budget_meter_parts(&builder, MINT_D, now);

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let deploy_sign = deploy;
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("mint").args_with(move |tx, input_idx| {
                let reused = SigHashReusedValuesUnsync::new();
                let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
                let mut sig = deploy_sign.sign_schnorr(secp256k1::Message::from_digest(hash.as_bytes())).as_ref().to_vec();
                sig.push(SIG_HASH_ALL.to_u8());
                vec![ArgValue::Value(ArtifactValue::Int(MINT_D)), ArgValue::Value(ArtifactValue::Bytes(sig)), ArgValue::Value(ArtifactValue::Int(4))]
            }),
            vault_outpoint,
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .actor_output("vault_app::Vault", vault_out, kaspa_consensus_core::tx::CovenantBinding::new(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, kaspa_consensus_core::tx::CovenantBinding::new(1, kusd_covid), auth_value)
        .actor_output("kusd_app::Kusd", emitted, kaspa_consensus_core::tx::CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, kaspa_consensus_core::tx::CovenantBinding::new(2, oracle_covid), oracle_value)
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(MINT_D)), ArgValue::Value(ArtifactValue::Int(4)), ArgValue::Value(ArtifactValue::Bytes(xonly(&keypair("deploy"))))]),
            b_outpoint,
            b_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("budget_app::Budget", b_out, binding(3, b_covid), b_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount);
    let mut tx = builder.build(&context).expect("mint tx");
    let txid = preverify_and_submit("MINT", &mut tx, vec![vault_utxo, auth_utxo, ora_utxo, b_utxo, funding], client).await;
    record_box("budget", b_covid, txid, 4, b_value, b_extra);
    record_box(&vault_name, vault_covid, txid, 0, vault_value_out, serde_json::json!({"collateral": collateral, "debt": debt + MINT_D}));
    record_box("authority", kusd_covid, txid, 1, auth_value, serde_json::json!({"amount": auth_amount - MINT_D, "ext": hex32(&gate.ext)}));
    record_box(&minted_name, kusd_covid, txid, 2, DUST, serde_json::json!({"amount": MINT_D, "owner": "deploy"}));
    record_box("oracle", oracle_covid, txid, 3, oracle_value, oracle_extra.clone());
    println!("*** LIVE USD-DENOMINATED MINT: {} cents of kUSD against {} sompi collateral at mint_price {} (1e-4 USD/KAS; raw {}) — metered by the global budget ***", MINT_D, collateral, mint_p, price);
}

async fn swap_in(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (psm_covid, psm_outpoint, psm_value, psm_extra) = box_info("psm");
    assert!(psm_extra["wired"].as_bool().unwrap_or(false), "psm not wired");

    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (ceiling, minted) = (psm_extra["ceiling"].as_i64().unwrap(), psm_extra["minted"].as_i64().unwrap());

    let deploy = keypair("deploy");
    let kas_in = kusd_v2_harness::sompi_of_ceil(SWAP_C, mint_p) as u64;
    let psm_value_out = psm_value + kas_in;
    let need = kas_in + DUST + FEE + DUST;
    let (fund_outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - kas_in - DUST - FEE;
    let now = funding.block_daa_score as i64;

    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount - SWAP_C, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let emitted = kusd_state_map(SWAP_C, xonly(&deploy), 0x00, gate.ext.clone());
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let psm_in = psm_state_map(ceiling, minted, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());
    let psm_out = psm_state_map(ceiling, minted + SWAP_C, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let (b_in, b_out, b_utxo, b_covid, b_outpoint, b_value, b_extra) = budget_meter_parts(&builder, SWAP_C, now);
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let recipient = xonly(&deploy);
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(SWAP_C)), ArgValue::Value(ArtifactValue::Bytes(recipient.clone())), ArgValue::Value(ArtifactValue::Int(3))]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("psm_app::Psm", psm_out, kaspa_consensus_core::tx::CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, kaspa_consensus_core::tx::CovenantBinding::new(1, kusd_covid), auth_value)
        .actor_output("kusd_app::Kusd", emitted, kaspa_consensus_core::tx::CovenantBinding::new(1, kusd_covid), DUST)
        .actor_output("oracle_app::Oracle", ora, kaspa_consensus_core::tx::CovenantBinding::new(2, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change)
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(SWAP_C)), ArgValue::Value(ArtifactValue::Int(3)), ArgValue::Value(ArtifactValue::Bytes(xonly(&keypair("deploy"))))]),
            b_outpoint,
            b_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, binding(4, b_covid), b_value);
    let mut tx = builder.build(&context).expect("swap_in tx");
    let txid = preverify_and_submit("SWAP_IN", &mut tx, vec![psm_utxo, auth_utxo, ora_utxo, funding, b_utxo], client).await;
    record_box("budget", b_covid, txid, 5, b_value, b_extra);
    record_box("psm", psm_covid, txid, 0, psm_value_out, serde_json::json!({"ceiling": ceiling, "minted": minted + SWAP_C, "wired": true}));
    record_box("authority", kusd_covid, txid, 1, auth_value, serde_json::json!({"amount": auth_amount - SWAP_C, "ext": hex32(&gate.ext)}));
    record_box("swap_holder", kusd_covid, txid, 2, DUST, serde_json::json!({"amount": SWAP_C, "owner": "deploy"}));
    record_box("oracle", oracle_covid, txid, 3, oracle_value, oracle_extra.clone());
    println!("*** LIVE SWAP_IN: reserve +{kas_in} sompi, {SWAP_C} cents minted ***");
}

async fn swap_out(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (psm_covid, psm_outpoint, psm_value, psm_extra) = box_info("psm");
    let (_, holder_outpoint, holder_value, holder_extra) = box_info("swap_holder");

    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (ceiling, minted) = (psm_extra["ceiling"].as_i64().unwrap(), psm_extra["minted"].as_i64().unwrap());
    let c = holder_extra["amount"].as_i64().unwrap();

    let deploy = keypair("deploy");
    let kas_out = kusd_v2_harness::sompi_of(c, liq_p) as u64;
    let psm_value_out = psm_value - kas_out;

    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount + c, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let holder = kusd_state_map(c, xonly(&deploy), 0x00, gate.ext.clone());
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let psm_in = psm_state_map(ceiling, minted, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());
    let psm_out = psm_state_map(ceiling, minted - c, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), holder_value, 0, false, Some(kusd_covid)).expect("holder utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");

    // fee comes from the holder box value (burned box frees its dust)
    let payout = kas_out;
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let redeemer = xonly(&deploy);
    let burner = deploy;
    let mut payout_spk = vec![0x20];
    payout_spk.extend_from_slice(&redeemer);
    payout_spk.push(0xac);

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_out").args_with(move |tx, input_idx| {
                let reused = SigHashReusedValuesUnsync::new();
                let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
                let mut sig = burner.sign_schnorr(secp256k1::Message::from_digest(hash.as_bytes())).as_ref().to_vec();
                sig.push(SIG_HASH_ALL.to_u8());
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sig)),
                    ArgValue::Value(ArtifactValue::Int(4)),
                ]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &keypair("deploy"))))]
            }),
            holder_outpoint,
            holder_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, kaspa_consensus_core::tx::CovenantBinding::new(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, kaspa_consensus_core::tx::CovenantBinding::new(1, kusd_covid), auth_value + holder_value - FEE)
        .output(kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, payout_spk), None, payout)
        .actor_output("oracle_app::Oracle", ora, kaspa_consensus_core::tx::CovenantBinding::new(3, oracle_covid), oracle_value);
    // net metering: the burn credits the global budget; clock = the funding input
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    let (cb_in, cb_out, cb_utxo, cb_covid, cb_outpoint, cb_value, cb_extra) = budget_credit_parts(&builder, c, now);
    let credit_r = c;
    let context = context
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_input(
            "budget_app::Budget",
            cb_in,
            EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(credit_r)), ArgValue::Value(ArtifactValue::Int(4))]),
            cb_outpoint,
            cb_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", cb_out, binding(5, cb_covid), cb_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount);
    let mut tx = builder.build(&context).expect("swap_out tx");
    let txid = preverify_and_submit("SWAP_OUT", &mut tx, vec![psm_utxo, auth_utxo, holder_utxo, ora_utxo, funding, cb_utxo], client).await;
    record_box("budget", cb_covid, txid, 4, cb_value, cb_extra);
    record_box("psm", psm_covid, txid, 0, psm_value_out, serde_json::json!({"ceiling": ceiling, "minted": minted - c, "wired": true}));
    record_box("authority", kusd_covid, txid, 1, auth_value + holder_value - FEE, serde_json::json!({"amount": auth_amount + c, "ext": hex32(&gate.ext)}));
    record_box("oracle", oracle_covid, txid, 3, oracle_value, oracle_extra.clone());
    println!("*** LIVE SWAP_OUT (redemption): {c} cents burned, {payout} sompi paid out at {price} c/KAS ***");
}

// --- phase-3b exercise stages -----------------------------------------------

fn env_name(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn remove_box(name: &str) {
    let mut st = load_state();
    st.as_object_mut().unwrap().remove(name);
    save_state(&st);
}

fn binding(input: u16, covid: Hash) -> kaspa_consensus_core::tx::CovenantBinding {
    kaspa_consensus_core::tx::CovenantBinding::new(input, covid)
}

/// Custody move: a kUSD holder box -> a (fresh) key, 1-in/1-out, value conserved.
/// Env: HOLDER_BOX (default "minted"), TO (default "user2").
async fn transfer(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let box_name = env_name("HOLDER_BOX", "minted");
    let to_name = env_name("TO", "user2");
    let (kusd_covid, h_outpoint, h_value, h_extra) = box_info(&box_name);
    let amount = h_extra["amount"].as_i64().unwrap();
    let from_name = h_extra["owner"].as_str().unwrap().to_string();
    let from = keypair(&from_name);
    let to = keypair(&to_name);

    let h_in = kusd_state_map(amount, xonly(&from), 0x00, gate.ext.clone());
    let h_out = kusd_state_map(amount, xonly(&to), 0x00, gate.ext.clone());
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", h_in.clone(), h_value, 0, false, Some(kusd_covid)).expect("holder utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let new_states = ArtifactValue::Array(vec![obj(h_out.clone())]);
    let signer = from;
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            h_in,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                let mut w = vec![0x00u8]; // PATH_NORMAL
                w.extend_from_slice(&sign_input(tx, input_idx, &signer));
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
            }),
            h_outpoint,
            h_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("kusd_app::Kusd", h_out, binding(0, kusd_covid), h_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("transfer tx");
    let txid = preverify_and_submit("TRANSFER", &mut tx, vec![h_utxo, funding], client).await;
    record_box(&box_name, kusd_covid, txid, 0, h_value, serde_json::json!({"amount": amount, "owner": to_name}));
    println!("*** LIVE TRANSFER: {amount} cents of kUSD {from_name} -> {to_name} (custody move, value conserved) ***");
}

/// Committee price refresh (2-of-3 by index). Env: PRICE, EPOCH, IDX_A, IDX_B.
async fn refresh(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let g = |k: &str| oracle_extra[k].as_i64().unwrap();
    let (old_price, old_mint, old_liq, old_epoch, old_last) = (g("price"), g("mint"), g("liq"), g("epoch"), g("last"));
    let new_epoch = env_i64("EPOCH", old_epoch + 1);
    // three operators' independent prints: OPS="0,1,2", PRICES="a,b,c" (default all PRICE)
    let ops: Vec<i64> = env_name("OPS", "0,1,2").split(',').map(|s| s.trim().parse().unwrap()).collect();
    let base = env_i64("PRICE", 4_500);
    let prices: Vec<i64> = std::env::var("PRICES").map(|s| s.split(',').map(|x| x.trim().parse().unwrap()).collect()).unwrap_or_else(|_| vec![base; 3]);
    assert!(ops.len() == 3 && prices.len() == 3, "need exactly three operators and three prices");
    let mut sorted = prices.clone();
    sorted.sort();
    let median = sorted[1];

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    // operators stamp prints with the current DAA (here: the funding input's
    // confirmation, which is also the clock input proving no print is future-dated)
    let now = funding.block_daa_score as i64;
    assert!(now >= old_last, "funding utxo older than last_update — run STAGE=touch first");
    let elapsed = (now - old_last).min(36_000); // RATE_WINDOW
    let mint = if median <= old_mint { median } else { median.min(old_mint + rate_step(old_mint, elapsed, 360_000)) };
    let liq = if median >= old_liq { median } else { median.max(old_liq - rate_step(old_liq, elapsed, 144_000)) };

    // each operator signs its own print OFFLINE (here: from its key file); the
    // relayer (this driver) just assembles them
    let mut args: Vec<ArtifactValue> = vec![ArtifactValue::Int(new_epoch)];
    for k in 0..3 {
        let op = keypair(&operator_name(ops[k] as usize));
        let digest = kusd_v2_harness::print_digest(oracle_covid.as_bytes(), new_epoch, prices[k], now);
        args.push(ArtifactValue::Int(ops[k]));
        args.push(ArtifactValue::Int(prices[k]));
        args.push(ArtifactValue::Int(now));
        args.push(ArtifactValue::Bytes(kusd_v2_harness::sign_digest(&op, digest)));
    }
    args.push(ArtifactValue::Int(1));

    let ora_in = oracle_map_from(&oracle_extra);
    let ora_out = oracle_map(median, mint, liq, new_epoch, now, 0);
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora_in.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");
    let change = funding.amount - FEE;
    let context = TxContext::new()
        .actor_input(
            "oracle_app::Oracle",
            ora_in,
            EntryCall::new("refresh").args_with(move |_tx, _idx| args.iter().cloned().map(ArgValue::Value).collect()),
            oracle_outpoint,
            ora_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("oracle_app::Oracle", ora_out, binding(0, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("refresh tx");
    let txid = preverify_and_submit("REFRESH", &mut tx, vec![ora_utxo, funding], client).await;
    record_box("oracle", oracle_covid, txid, 0, oracle_value, oracle_extra_json(median, mint, liq, new_epoch, now, 0));
    println!("*** LIVE ORACLE REFRESH: operators {ops:?} printed {prices:?} -> median {median}; mint_price {old_mint} -> {mint}, liq_price {old_liq} -> {liq} (raw was {old_price}) ***");
}

/// Operator rotation: SLOT gets the key named NEW_KEY (fresh TN10 key), signed
/// by three operators SIGNERS="a,b,c" (none of them the replaced slot).
async fn set_member(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let slot = env_i64("SLOT", 4);
    let new_name = env_name("NEW_KEY", "oracle5");
    let signers: Vec<i64> = env_name("SIGNERS", "0,1,2").split(',').map(|s| s.trim().parse().unwrap()).collect();
    assert_eq!(signers.len(), 3);
    assert!(!signers.contains(&slot), "the replaced slot can't sign its own rotation");
    let epoch = oracle_extra["epoch"].as_i64().unwrap();
    let new_key = xonly(&keypair(&new_name));
    let digest = kusd_v2_harness::member_digest(oracle_covid.as_bytes(), epoch, slot, &new_key);
    let mut args: Vec<ArtifactValue> = vec![ArtifactValue::Int(slot), ArtifactValue::Bytes(new_key.clone())];
    for s in &signers {
        args.push(ArtifactValue::Int(*s));
    }
    for s in &signers {
        args.push(ArtifactValue::Bytes(kusd_v2_harness::sign_digest(&keypair(&operator_name(*s as usize)), digest)));
    }
    let ora_in = oracle_map_from(&oracle_extra);
    // the continuation: slot rotated, epoch bumped
    let mut st = load_state();
    let mut names: Vec<String> = (0..5).map(operator_name).collect();
    names[slot as usize] = new_name.clone();
    st["operators"] = serde_json::json!(names);
    let mut next_extra = oracle_extra.clone();
    next_extra["epoch"] = serde_json::json!(epoch + 1);
    let k = |n: &String| xonly(&keypair(n));
    let ora_out = state! {
        price: next_extra["price"].as_i64().unwrap(),
        mint_price: next_extra["mint"].as_i64().unwrap(),
        liq_price: next_extra["liq"].as_i64().unwrap(),
        epoch: epoch + 1,
        last_update: next_extra["last"].as_i64().unwrap(),
        status: next_extra["status"].as_i64().unwrap(),
        m0: k(&names[0]),
        m1: k(&names[1]),
        m2: k(&names[2]),
        m3: k(&names[3]),
        m4: k(&names[4]),
    };
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora_in.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let context = TxContext::new()
        .actor_input(
            "oracle_app::Oracle",
            ora_in,
            EntryCall::new("set_member").args_with(move |_tx, _idx| args.iter().cloned().map(ArgValue::Value).collect()),
            oracle_outpoint,
            ora_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("oracle_app::Oracle", ora_out, binding(0, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("set_member tx");
    let txid = preverify_and_submit("SET_MEMBER", &mut tx, vec![ora_utxo, funding], client).await;
    save_state(&st);
    record_box("oracle", oracle_covid, txid, 0, oracle_value, next_extra);
    println!("*** LIVE OPERATOR ROTATION: slot {slot} -> {new_name}, signed by operators {signers:?} (3, none the replaced slot) ***");
}

/// Permissionless stale-feed transitions. Env: ENTRY = freeze | settle.
async fn oracle_status(client: &GrpcClient, entry: &str) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let new_status = if entry == "freeze" { 1 } else { 2 };
    let mut next_extra = oracle_extra.clone();
    next_extra["status"] = serde_json::json!(new_status);
    let ora_in = oracle_map_from(&oracle_extra);
    let ora_out = oracle_map_from(&next_extra);
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora_in.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let silent = funding.block_daa_score as i64 - oracle_extra["last"].as_i64().unwrap();
    println!("feed silent for {silent} DAA (freeze needs > 36000, settle > 25920000)");
    let change = funding.amount - FEE;
    let context = TxContext::new()
        .actor_input(
            "oracle_app::Oracle",
            ora_in,
            EntryCall::new(entry).args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(1))]),
            oracle_outpoint,
            ora_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("oracle_app::Oracle", ora_out, binding(0, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("oracle status tx");
    let label = if entry == "freeze" { "FREEZE" } else { "SETTLE" };
    let txid = preverify_and_submit(label, &mut tx, vec![ora_utxo, funding], client).await;
    record_box("oracle", oracle_covid, txid, 0, oracle_value, next_extra);
    println!("*** LIVE ORACLE {label}: anyone can stop a silent feed — status -> {new_status} ***");
}

/// Global mint budget genesis, UNWIRED (before the authority).
async fn budget_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let need = DUST + FEE + DUST;
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - DUST - FEE;
    let last = funding.block_daa_score as i64;
    let st = budget_map(BUDGET_LIMIT, BUDGET_LIMIT, last, vec![0u8; 32]);
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::budget", "budget_app::Budget", st, DUST)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("budget genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("BUDGET-GENESIS", &mut tx, vec![funding], client).await;
    record_box("budget", root.covenant_id, txid, 0, DUST, serde_json::json!({"limit": BUDGET_LIMIT, "available": BUDGET_LIMIT, "last": last, "wired": false}));
}

/// One-time governance wiring of the budget to the kUSD authority.
async fn budget_wire(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (kusd_covid, _, _, _) = box_info("authority");
    let (b_covid, b_outpoint, b_value, b_extra) = box_info("budget");
    let g = |k: &str| b_extra[k].as_i64().unwrap();
    let b_in = budget_map(g("limit"), g("available"), g("last"), vec![0u8; 32]);
    let b_out = budget_map(g("limit"), g("available"), g("last"), kusd_covid.as_bytes().to_vec());
    let b_utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), b_value, 0, false, Some(b_covid)).expect("budget utxo");
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let (ga, gb) = (keypair("gov0"), keypair("gov2"));
    let kusd_arg = kusd_covid.as_bytes().to_vec();
    let context = TxContext::new()
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("wire").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Bytes(kusd_arg.clone())),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ga))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &gb))),
                ]
            }),
            b_outpoint,
            b_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("budget_app::Budget", b_out, binding(0, b_covid), b_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("budget wire tx");
    let txid = preverify_and_submit("BUDGET-WIRE", &mut tx, vec![b_utxo, funding], client).await;
    let mut extra = b_extra.clone();
    extra["wired"] = serde_json::json!(true);
    record_box("budget", b_covid, txid, 0, b_value, extra);
}

/// Governance changes the daily issuance limit to NEW_LIMIT (cents), 2-of-3
/// (gov0 + gov2); the refill accrued at the OLD limit is settled first, and
/// `available` is clamped to the new limit. Clock: the funding input.
async fn budget_set_limit(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (kusd_covid, _, _, _) = box_info("authority");
    let (b_covid, b_outpoint, b_value, b_extra) = box_info("budget");
    let g = |k: &str| b_extra[k].as_i64().unwrap();
    let (limit, available, last) = (g("limit"), g("available"), g("last"));
    let new_limit = env_i64("NEW_LIMIT", limit);
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    assert!(now >= last, "funding utxo older than the budget's last_refill — run STAGE=touch first");
    let next_available = kusd_v2_harness::budget_refill(limit, available, last, now).min(new_limit);
    let b_in = budget_map(limit, available, last, kusd_covid.as_bytes().to_vec());
    let b_out = budget_map(new_limit, next_available, now, kusd_covid.as_bytes().to_vec());
    let b_utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), b_value, 0, false, Some(b_covid)).expect("budget utxo");
    let change = funding.amount - FEE;
    let (ga, gb) = (keypair("gov0"), keypair("gov2"));
    let context = TxContext::new()
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("set_limit").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(new_limit)),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ga))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &gb))),
                    ArgValue::Value(ArtifactValue::Int(1)),
                ]
            }),
            b_outpoint,
            b_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("budget_app::Budget", b_out, binding(0, b_covid), b_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("set_limit tx");
    let txid = preverify_and_submit("BUDGET-SET-LIMIT", &mut tx, vec![b_utxo, funding], client).await;
    let mut extra = b_extra.clone();
    extra["limit"] = serde_json::json!(new_limit);
    extra["available"] = serde_json::json!(next_available);
    extra["last"] = serde_json::json!(now);
    record_box("budget", b_covid, txid, 0, b_value, extra);
    println!("*** LIVE BUDGET SET_LIMIT (gov 2-of-3): daily limit {limit} -> {new_limit} cents; available {available} -> {next_available} ***");
}

/// Budget input + continuation crediting `r` burned cents with clock `now`.
fn budget_credit_parts(builder: &TxBuilder<'_>, r: i64, now: i64) -> (BTreeMap<String, ArtifactValue>, BTreeMap<String, ArtifactValue>, UtxoEntry, Hash, TransactionOutpoint, u64, serde_json::Value) {
    let (kusd_covid, _, _, _) = box_info("authority");
    let (b_covid, b_outpoint, b_value, b_extra) = box_info("budget");
    let g = |k: &str| b_extra[k].as_i64().unwrap();
    let (limit, available, last) = (g("limit"), g("available"), g("last"));
    assert!(now >= last, "clock older than the budget's last_refill");
    let refunded = (kusd_v2_harness::budget_refill(limit, available, last, now) + r).min(limit);
    let b_in = budget_map(limit, available, last, kusd_covid.as_bytes().to_vec());
    let b_out = budget_map(limit, refunded, now, kusd_covid.as_bytes().to_vec());
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), b_value, 0, false, Some(b_covid)).expect("budget utxo");
    let mut extra = b_extra.clone();
    extra["available"] = serde_json::json!(refunded);
    extra["last"] = serde_json::json!(now);
    (b_in, b_out, utxo, b_covid, b_outpoint, b_value, extra)
}

/// Budget input + continuation metering `d` with clock `now`; returns the
/// (input state, output state, utxo, next extra).
fn budget_meter_parts(builder: &TxBuilder<'_>, d: i64, now: i64) -> (BTreeMap<String, ArtifactValue>, BTreeMap<String, ArtifactValue>, UtxoEntry, Hash, TransactionOutpoint, u64, serde_json::Value) {
    let (kusd_covid, _, _, _) = box_info("authority");
    let (b_covid, b_outpoint, b_value, b_extra) = box_info("budget");
    let g = |k: &str| b_extra[k].as_i64().unwrap();
    let (limit, available, last) = (g("limit"), g("available"), g("last"));
    assert!(now >= last, "clock older than the budget's last_refill");
    let avail = kusd_v2_harness::budget_refill(limit, available, last, now);
    assert!(d <= avail, "global mint budget exhausted: {avail} cents available, {d} requested");
    let b_in = budget_map(limit, available, last, kusd_covid.as_bytes().to_vec());
    let b_out = budget_map(limit, avail - d, now, kusd_covid.as_bytes().to_vec());
    let utxo = builder.covenant_utxo("budget_app::Budget", b_in.clone(), b_value, 0, false, Some(b_covid)).expect("budget utxo");
    let mut extra = b_extra.clone();
    extra["available"] = serde_json::json!(avail - d);
    extra["last"] = serde_json::json!(now);
    (b_in, b_out, utxo, b_covid, b_outpoint, b_value, extra)
}

/// Vault collateral adjust under the frozen kusd family. Env: DELTA (sompi), VAULT_BOX.
async fn adjust(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let vault_name = env_name("VAULT_BOX", "vault");
    let delta = env_i64("DELTA", 100_000_000);
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (vault_covid, vault_outpoint, vault_value, vault_extra) = box_info(&vault_name);
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (collateral, debt) = (vault_extra["collateral"].as_i64().unwrap(), vault_extra["debt"].as_i64().unwrap());

    let deploy = keypair("deploy");
    let ora = oracle_map_from(&oracle_extra);
    let auth = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let vault_in = vault_state_map(collateral, debt, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_out = vault_state_map(collateral + delta, debt, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_value_out = TOMBSTONE + (collateral + delta) as u64;

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let (fund_outpoint, funding) = pick_funding(client, vault_value_out + 2 * FEE).await;
    let change = vault_value + funding.amount - vault_value_out - FEE;
    let emission_states = ArtifactValue::Array(vec![obj(auth.clone())]);
    let signer = deploy;
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("adjust").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(delta)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer))),
                ]
            }),
            vault_outpoint,
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth.clone(),
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("vault_app::Vault", vault_out, binding(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth, binding(1, kusd_covid), auth_value)
        .actor_output("oracle_app::Oracle", ora, binding(2, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("adjust tx");
    let txid = preverify_and_submit("ADJUST", &mut tx, vec![vault_utxo, auth_utxo, ora_utxo, funding], client).await;
    record_box(&vault_name, vault_covid, txid, 0, vault_value_out, serde_json::json!({"collateral": collateral + delta, "debt": debt}));
    record_box("authority", kusd_covid, txid, 1, auth_value, auth_extra.clone());
    record_box("oracle", oracle_covid, txid, 2, oracle_value, oracle_extra.clone());
    println!("*** LIVE ADJUST: collateral {collateral} -> {} sompi (debt {debt} frozen, supply frozen) ***", collateral + delta);
}

/// Governance ceiling change on the PSM (2-of-3). Env: CEILING (cents).
async fn set_ceiling(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let new_ceiling = env_i64("CEILING", 50_000);
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (psm_covid, psm_outpoint, psm_value, psm_extra) = box_info("psm");
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (ceiling, minted) = (psm_extra["ceiling"].as_i64().unwrap(), psm_extra["minted"].as_i64().unwrap());

    let auth = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let spread_in = psm_extra["spread"].as_i64().unwrap_or(0);
    let new_spread = env_i64("SPREAD", spread_in);
    let psm_in = psm_state_map(ceiling, minted, spread_in, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());
    let psm_out = psm_state_map(new_ceiling, minted, new_spread, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec(), budget_id_bytes());

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let (ga, gb) = (keypair("gov0"), keypair("gov2"));
    let emission_states = ArtifactValue::Array(vec![obj(auth.clone())]);
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("set_params").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(new_ceiling)),
                    ArgValue::Value(ArtifactValue::Int(new_spread)),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ga))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &gb))),
                ]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth.clone(),
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("psm_app::Psm", psm_out, binding(0, psm_covid), psm_value)
        .actor_output("kusd_app::Kusd", auth, binding(1, kusd_covid), auth_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("set_ceiling tx");
    let txid = preverify_and_submit("SET_CEILING", &mut tx, vec![psm_utxo, auth_utxo, funding], client).await;
    record_box("psm", psm_covid, txid, 0, psm_value, serde_json::json!({"ceiling": new_ceiling, "minted": minted, "spread": new_spread, "wired": true}));
    record_box("authority", kusd_covid, txid, 1, auth_value, auth_extra.clone());
    println!("*** LIVE SET_CEILING: {ceiling} -> {new_ceiling} cents (gov 2-of-3) ***");
}

/// Repay vault debt by burning a holder box owned by the vault owner; full
/// repay (r == debt) releases collateral. Env: VAULT_BOX, HOLDER_BOX, NEXT_COLLATERAL.
async fn repay(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let vault_name = env_name("VAULT_BOX", "vault");
    let holder_name = env_name("HOLDER_BOX", "minted");
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (vault_covid, vault_outpoint, vault_value, vault_extra) = box_info(&vault_name);
    let (surplus_covid_h, surplus_outpoint, surplus_value, _) = box_info("surplus");
    let (_, holder_outpoint, holder_value, holder_extra) = box_info(&holder_name);
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (collateral, debt) = (vault_extra["collateral"].as_i64().unwrap(), vault_extra["debt"].as_i64().unwrap());
    let r = holder_extra["amount"].as_i64().unwrap();
    assert_eq!(r, debt, "exercise is a FULL repay");
    let next_collateral = env_i64("NEXT_COLLATERAL", 0);
    let owner_name = holder_extra["owner"].as_str().unwrap().to_string();

    let deploy = keypair(&owner_name);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount + r, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let holder = kusd_state_map(r, xonly(&deploy), 0x00, gate.ext.clone());
    let vault_in = vault_state_map(collateral, debt, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_out = vault_state_map(next_collateral, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_value_out = TOMBSTONE + next_collateral as u64;
    let released = vault_value - vault_value_out;

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), holder_value, 0, false, Some(kusd_covid)).expect("holder utxo");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let signer = deploy;
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("repay").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(r)),
                    ArgValue::Value(ArtifactValue::Int(next_collateral)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer))),
                    ArgValue::Value(ArtifactValue::Int(3)),
                ]
            }),
            vault_outpoint,
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with({
                let kp = deploy;
                move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp)))]
            }),
            holder_outpoint,
            holder_utxo.clone(),
            0,
        )
        .actor_output("vault_app::Vault", vault_out, binding(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, binding(1, kusd_covid), auth_value + holder_value - FEE)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, released);
    // net metering: the burn credits the global budget; clock = the funding input
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    let (cb_in, cb_out, cb_utxo, cb_covid, cb_outpoint, cb_value, cb_extra) = budget_credit_parts(&builder, r, now);
    let credit_r = r;
    let context = context
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_input(
            "budget_app::Budget",
            cb_in,
            EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(credit_r)), ArgValue::Value(ArtifactValue::Int(3))]),
            cb_outpoint,
            cb_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", cb_out, binding(4, cb_covid), cb_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount);
    let mut tx = builder.build(&context).expect("repay tx");
    let txid = preverify_and_submit("REPAY", &mut tx, vec![vault_utxo, auth_utxo, holder_utxo, funding, cb_utxo], client).await;
    record_box("budget", cb_covid, txid, 3, cb_value, cb_extra);
    record_box(&vault_name, vault_covid, txid, 0, vault_value_out, serde_json::json!({"collateral": next_collateral, "debt": 0}));
    record_box("authority", kusd_covid, txid, 1, auth_value + holder_value - FEE, serde_json::json!({"amount": auth_amount + r, "ext": hex32(&gate.ext)}));
    remove_box(&holder_name);
    println!("*** LIVE FULL REPAY: {r} cents burned, debt 0, {released} sompi collateral RELEASED ***");
}

/// Liquidate an unhealthy vault: keeper burns kUSD == debt, takes seized
/// collateral (13% penalty, capped) at a forced P2PK payout. Env: VAULT_BOX, HOLDER_BOX.
async fn liquidate(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let vault_name = env_name("VAULT_BOX", "vault");
    let holder_name = env_name("HOLDER_BOX", "minted");
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (vault_covid, vault_outpoint, vault_value, vault_extra) = box_info(&vault_name);
    let (surplus_covid_h, surplus_outpoint, surplus_value, _) = box_info("surplus");
    let (_, holder_outpoint, holder_value, holder_extra) = box_info(&holder_name);
    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (collateral, debt) = (vault_extra["collateral"].as_i64().unwrap(), vault_extra["debt"].as_i64().unwrap());
    let keeper_name = holder_extra["owner"].as_str().unwrap().to_string();
    let keeper = keypair(&keeper_name);
    assert_eq!(holder_extra["amount"].as_i64().unwrap(), debt, "keeper burns exactly the debt");

    // contract's split math: keeper 110% of debt, surplus 3%, keeper first on cap
    let mut keeper_sompi = kusd_v2_harness::sompi_of(debt * 11_000 / 10_000, liq_p.max(1));
    let mut surplus_sompi = kusd_v2_harness::sompi_of(debt * 300 / 10_000, liq_p.max(1));
    let freed = collateral - TOMBSTONE as i64;
    if keeper_sompi > freed {
        keeper_sompi = freed;
    }
    if keeper_sompi < TOMBSTONE as i64 {
        keeper_sompi = TOMBSTONE as i64; // contract's KIP-9 clamp
    }
    if keeper_sompi > freed {
        keeper_sompi = freed;
    }
    if surplus_sompi > freed - keeper_sompi {
        surplus_sompi = freed - keeper_sompi;
    }
    let closed_collateral = collateral - keeper_sompi - surplus_sompi;

    let deploy_owner = keypair("deploy"); // vault owner stays on the continuation
    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount + debt, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let holder = kusd_state_map(debt, xonly(&keeper), 0x00, gate.ext.clone());
    let vault_in = vault_state_map(collateral, debt, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_out = vault_state_map(closed_collateral, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());
    let vault_value_out = TOMBSTONE + closed_collateral as u64;
    let _ = &deploy_owner;

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), holder_value, 0, false, Some(kusd_covid)).expect("holder utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");
    let s_in = surplus_state_map(vec![0u8; 32]);
    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), surplus_value, 0, false, Some(surplus_covid_h)).expect("surplus utxo");
    let s_value_out = (surplus_value as i64 + surplus_sompi) as u64;

    let mut payout_spk = vec![0x20];
    payout_spk.extend_from_slice(&xonly(&keeper));
    payout_spk.push(0xac);

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let burner = keeper;
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("liquidate").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &burner))), ArgValue::Value(ArtifactValue::Int(5))]
            }),
            vault_outpoint,
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with({
                let kp = keeper;
                move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp)))]
            }),
            holder_outpoint,
            holder_utxo.clone(),
            0,
        )
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", surplus_outpoint, s_utxo.clone(), 0)
        .actor_output("vault_app::Vault", vault_out, binding(0, vault_covid), vault_value_out)
        .actor_output("kusd_app::Kusd", auth_out, binding(1, kusd_covid), auth_value + holder_value - FEE)
        .output(kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, payout_spk), None, keeper_sompi as u64)
        .actor_output("surplus_app::Surplus", s_in, binding(4, surplus_covid_h), s_value_out)
        .actor_output("oracle_app::Oracle", ora, binding(3, oracle_covid), oracle_value);
    // net metering: the burn credits the global budget; clock = the funding input
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    let (cb_in, cb_out, cb_utxo, cb_covid, cb_outpoint, cb_value, cb_extra) = budget_credit_parts(&builder, debt, now);
    let credit_r = debt;
    let context = context
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_input(
            "budget_app::Budget",
            cb_in,
            EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(credit_r)), ArgValue::Value(ArtifactValue::Int(5))]),
            cb_outpoint,
            cb_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", cb_out, binding(6, cb_covid), cb_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount);
    let mut tx = builder.build(&context).expect("liquidate tx");
    let txid = preverify_and_submit("LIQUIDATE", &mut tx, vec![vault_utxo, auth_utxo, holder_utxo, ora_utxo, s_utxo, funding, cb_utxo], client).await;
    record_box("budget", cb_covid, txid, 5, cb_value, cb_extra);
    record_box(&vault_name, vault_covid, txid, 0, vault_value_out, serde_json::json!({"collateral": closed_collateral, "debt": 0}));
    record_box("authority", kusd_covid, txid, 1, auth_value + holder_value - FEE, serde_json::json!({"amount": auth_amount + debt, "ext": hex32(&gate.ext)}));
    record_box("oracle", oracle_covid, txid, 4, oracle_value, oracle_extra.clone());
    record_box("surplus", surplus_covid_h, txid, 3, s_value_out, serde_json::json!({}));
    remove_box(&holder_name);
    println!("*** LIVE LIQUIDATE: {debt} cents burned at liq_price {liq_p} (1e-4 USD/KAS); keeper '{keeper_name}' seized {keeper_sompi} sompi, surplus took {surplus_sompi} (110/3 split, keeper-first cap) ***");
}

/// Authority owner-key rotation (scheme 2, standalone: no other covenant inputs).
/// Env: SIGNER (current owner key name, default gov0), NEW_OWNER (default gov1).
async fn rotate(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let signer_name = env_name("SIGNER", "gov0");
    let new_name = env_name("NEW_OWNER", "gov1");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let signer = keypair(&signer_name);
    let new_owner = xonly(&keypair(&new_name));

    let auth_in = kusd_state_map(auth_amount, xonly(&signer), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount, new_owner.clone(), 0x10, gate.ext.clone());
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let new_owner_arg = new_owner;
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("rotate").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Bytes(new_owner_arg.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer))),
                ]
            }),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("kusd_app::Kusd", auth_out, binding(0, kusd_covid), auth_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("rotate tx");
    let txid = preverify_and_submit("ROTATE", &mut tx, vec![auth_utxo, funding], client).await;
    record_box("authority", kusd_covid, txid, 0, auth_value, serde_json::json!({"amount": auth_amount, "ext": hex32(&gate.ext), "owner": new_name}));
    println!("*** LIVE ROTATE: authority owner {signer_name} -> {new_name} ***");
}


// --- phase-4 stages -----------------------------------------------------------

/// Governance surplus box genesis (after the authority; its state needs only
/// the gov keys + KUSD_COVID).
async fn surplus_genesis(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    // geneses BEFORE the authority (review C2: its covid joins the gate config);
    // kusd_id is informational and stays zeros for the frozen lineage
    let need = TOMBSTONE + FEE + DUST;
    let (outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - TOMBSTONE - FEE;
    let st = surplus_state_map(vec![0u8; 32]);
    let context = TxContext::new()
        .input(outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_genesis_output(0, "launch::surplus", "surplus_app::Surplus", st, TOMBSTONE)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("surplus genesis tx");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    let txid = preverify_and_submit("SURPLUS-GENESIS", &mut tx, vec![funding], client).await;
    record_box("surplus", root.covenant_id, txid, 0, TOMBSTONE, serde_json::json!({}));
}

/// Bootstrap JSON for the budget genesis verify cross-check (BOOT_LAST = its last_refill).
fn budget_bootstrap_json() {
    let txid = std::env::var("BOOT_TXID").expect("BOOT_TXID (funding outpoint txid)");
    let index: u32 = std::env::var("BOOT_INDEX").map(|s| s.parse().unwrap()).unwrap_or(0);
    let last: i64 = std::env::var("BOOT_LAST").map(|s| s.parse().unwrap()).expect("BOOT_LAST");
    let int = |v: i64| serde_json::json!({"kind": "int", "value": v});
    let bytes = |v: Vec<u8>| serde_json::json!({"kind": "bytes", "value": v});
    let boot = serde_json::json!({
        "app": "BudgetApp",
        "authorizing_outpoint": {"transactionId": txid, "index": index},
        "outputs": [{
            "index": 0,
            "value": DUST,
            "actor": "Budget",
            "authored_state": {
                "daily_limit": int(BUDGET_LIMIT),
                "available": int(BUDGET_LIMIT),
                "last_refill": int(last),
                "kusd_id": bytes(vec![0u8; 32]),
                "g0": bytes(xonly(&keypair("gov0"))),
                "g1": bytes(xonly(&keypair("gov1"))),
                "g2": bytes(xonly(&keypair("gov2"))),
            }
        }]
    });
    println!("{}", serde_json::to_string_pretty(&boot).unwrap());
}

/// Bootstrap JSON for the surplus genesis verify cross-check.
fn surplus_bootstrap_json() {
    let txid = std::env::var("BOOT_TXID").expect("BOOT_TXID (funding outpoint txid)");
    let index: u32 = std::env::var("BOOT_INDEX").map(|s| s.parse().unwrap()).unwrap_or(0);
    let bytes = |v: Vec<u8>| serde_json::json!({"kind": "bytes", "value": v});
    let boot = serde_json::json!({
        "app": "SurplusApp",
        "authorizing_outpoint": {"transactionId": txid, "index": index},
        "outputs": [{
            "index": 0,
            "value": TOMBSTONE,
            "actor": "Surplus",
            "authored_state": {
                "g0": bytes(xonly(&keypair("gov0"))),
                "g1": bytes(xonly(&keypair("gov1"))),
                "g2": bytes(xonly(&keypair("gov2"))),
                "kusd_id": bytes(vec![0u8; 32]),
            }
        }]
    });
    println!("{}", serde_json::to_string_pretty(&boot).unwrap());
}

/// Fee-switch mint: as swapin, with the spread routed to the surplus box.
/// Env: SWAP_CENTS (default SWAP_C).
async fn swap_in_fee(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (psm_covid, psm_outpoint, psm_value, psm_extra) = box_info("psm");
    let (surplus_covid, surplus_outpoint, surplus_value, _) = box_info("surplus");
    let c = env_i64("SWAP_CENTS", SWAP_C);
    let spread = psm_extra["spread"].as_i64().unwrap_or(0);
    assert!(spread > 0, "fee switch is off; run STAGE=setparams SPREAD=25 first");

    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (ceiling, minted) = (psm_extra["ceiling"].as_i64().unwrap(), psm_extra["minted"].as_i64().unwrap());

    let deploy = keypair("deploy");
    let kas_in = kusd_v2_harness::sompi_of_ceil(c, mint_p);
    let fee = kas_in * spread / 10_000;
    let psm_value_out = (psm_value as i64 + kas_in) as u64;
    let s_value_out = (surplus_value as i64 + fee) as u64;
    let need = (kas_in + fee) as u64 + DUST + FEE + DUST;
    let (fund_outpoint, funding) = pick_funding(client, need).await;
    let change = funding.amount - (kas_in + fee) as u64 - DUST - FEE;
    let now = funding.block_daa_score as i64;
    let (b_in, b_out, b_utxo, b_covid, b_outpoint, b_value, b_extra) = budget_meter_parts(&builder, c, now);

    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount - c, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let emitted = kusd_state_map(c, xonly(&deploy), 0x00, gate.ext.clone());
    let psm_in = psm_state_map(ceiling, minted, spread, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid.as_bytes().to_vec(), budget_id_bytes());
    let psm_out = psm_state_map(ceiling, minted + c, spread, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid.as_bytes().to_vec(), budget_id_bytes());
    let s_in = surplus_state_map(vec![0u8; 32]);

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), surplus_value, 0, false, Some(surplus_covid)).expect("surplus utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone()), obj(emitted.clone())]);
    let recipient = xonly(&deploy);
    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_in_fee").args_with(move |_tx, _idx| {
                vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Bytes(recipient.clone())), ArgValue::Value(ArtifactValue::Int(4))]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", surplus_outpoint, s_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("psm_app::Psm", psm_out, binding(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, binding(1, kusd_covid), auth_value)
        .actor_output("kusd_app::Kusd", emitted, binding(1, kusd_covid), DUST)
        .actor_output("surplus_app::Surplus", s_in, binding(2, surplus_covid), s_value_out)
        .actor_output("oracle_app::Oracle", ora, binding(3, oracle_covid), oracle_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let context = context
        .actor_input(
            "budget_app::Budget",
            b_in,
            EntryCall::new("meter").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(c)), ArgValue::Value(ArtifactValue::Int(4)), ArgValue::Value(ArtifactValue::Bytes(xonly(&keypair("deploy"))))]),
            b_outpoint,
            b_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", b_out, binding(5, b_covid), b_value);
    let mut tx = builder.build(&context).expect("swap_in_fee tx");
    let txid = preverify_and_submit("SWAP_IN_FEE", &mut tx, vec![psm_utxo, auth_utxo, s_utxo, ora_utxo, funding, b_utxo], client).await;
    record_box("budget", b_covid, txid, 6, b_value, b_extra);
    record_box("psm", psm_covid, txid, 0, psm_value_out, serde_json::json!({"ceiling": ceiling, "minted": minted + c, "spread": spread, "wired": true}));
    record_box("authority", kusd_covid, txid, 1, auth_value, serde_json::json!({"amount": auth_amount - c, "ext": hex32(&gate.ext)}));
    record_box("swap_holder", kusd_covid, txid, 2, DUST, serde_json::json!({"amount": c, "owner": "deploy"}));
    record_box("surplus", surplus_covid, txid, 3, s_value_out, serde_json::json!({}));
    record_box("oracle", oracle_covid, txid, 4, oracle_value, oracle_extra.clone());
    println!("*** LIVE SWAP_IN_FEE: reserve +{kas_in}, SURPLUS +{fee} sompi at {spread} bps — protocol revenue on-chain ***");
}

/// Fee-switch redemption: spread taken out of the payout.
async fn swap_out_fee(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let (oracle_covid, oracle_outpoint, oracle_value, oracle_extra) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (psm_covid, psm_outpoint, psm_value, psm_extra) = box_info("psm");
    let (surplus_covid, surplus_outpoint, surplus_value, _) = box_info("surplus");
    let (_, holder_outpoint, holder_value, holder_extra) = box_info("swap_holder");
    let spread = psm_extra["spread"].as_i64().unwrap_or(0);
    assert!(spread > 0, "fee switch is off");

    let price = oracle_extra["price"].as_i64().unwrap();
    let (mint_p, liq_p) = (oracle_extra["mint"].as_i64().unwrap(), oracle_extra["liq"].as_i64().unwrap());
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (ceiling, minted) = (psm_extra["ceiling"].as_i64().unwrap(), psm_extra["minted"].as_i64().unwrap());
    let c = holder_extra["amount"].as_i64().unwrap();
    let holder_owner = holder_extra["owner"].as_str().unwrap().to_string();

    let deploy = keypair(&holder_owner);
    let kas_out = kusd_v2_harness::sompi_of(c, liq_p);
    let fee = kas_out * spread / 10_000;
    let psm_value_out = (psm_value as i64 - kas_out) as u64;
    let s_value_out = (surplus_value as i64 + fee) as u64;

    let ora = oracle_map_from(&oracle_extra);
    let auth_in = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let auth_out = kusd_state_map(auth_amount + c, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let holder = kusd_state_map(c, xonly(&deploy), 0x00, gate.ext.clone());
    let psm_in = psm_state_map(ceiling, minted, spread, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid.as_bytes().to_vec(), budget_id_bytes());
    let psm_out = psm_state_map(ceiling, minted - c, spread, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid.as_bytes().to_vec(), budget_id_bytes());
    let s_in = surplus_state_map(vec![0u8; 32]);

    let psm_utxo = builder.covenant_utxo("psm_app::Psm", psm_in.clone(), psm_value, 0, false, Some(psm_covid)).expect("psm utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth_in.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");
    let holder_utxo = builder.covenant_utxo("kusd_app::Kusd", holder.clone(), holder_value, 0, false, Some(kusd_covid)).expect("holder utxo");
    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), surplus_value, 0, false, Some(surplus_covid)).expect("surplus utxo");
    let ora_utxo = builder.covenant_utxo("oracle_app::Oracle", ora.clone(), oracle_value, 0, false, Some(oracle_covid)).expect("oracle utxo");

    let payout = (kas_out - fee) as u64;
    let emission_states = ArtifactValue::Array(vec![obj(auth_out.clone())]);
    let redeemer = xonly(&deploy);
    let burner = deploy;
    let mut payout_spk = vec![0x20];
    payout_spk.extend_from_slice(&redeemer);
    payout_spk.push(0xac);

    let context = TxContext::new()
        .actor_input(
            "psm_app::Psm",
            psm_in,
            EntryCall::new("swap_out_fee").args_with(move |tx, input_idx| {
                let mut sig = sign_input(tx, input_idx, &burner);
                sig.truncate(65);
                vec![
                    ArgValue::Value(ArtifactValue::Int(c)),
                    ArgValue::Value(ArtifactValue::Bytes(redeemer.clone())),
                    ArgValue::Value(ArtifactValue::Bytes(sig)),
                    ArgValue::Value(ArtifactValue::Int(5)),
                ]
            }),
            psm_outpoint,
            psm_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth_in,
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, true)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            holder,
            EntryCall::new("transfer_delegator").args_with({
                let kp = keypair(&holder_owner);
                move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp)))]
            }),
            holder_outpoint,
            holder_utxo.clone(),
            0,
        )
        .actor_input("surplus_app::Surplus", s_in.clone(), "receive", surplus_outpoint, s_utxo.clone(), 0)
        .actor_input("oracle_app::Oracle", ora.clone(), "peek", oracle_outpoint, ora_utxo.clone(), 0)
        .actor_output("psm_app::Psm", psm_out, binding(0, psm_covid), psm_value_out)
        .actor_output("kusd_app::Kusd", auth_out, binding(1, kusd_covid), auth_value + holder_value - FEE)
        .output(kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, payout_spk), None, payout)
        .actor_output("surplus_app::Surplus", s_in, binding(3, surplus_covid), s_value_out)
        .actor_output("oracle_app::Oracle", ora, binding(4, oracle_covid), oracle_value);
    // net metering: the burn credits the global budget; clock = the funding input
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let now = funding.block_daa_score as i64;
    let (cb_in, cb_out, cb_utxo, cb_covid, cb_outpoint, cb_value, cb_extra) = budget_credit_parts(&builder, c, now);
    let credit_r = c;
    let context = context
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_input(
            "budget_app::Budget",
            cb_in,
            EntryCall::new("credit").args_with(move |_tx, _idx| vec![ArgValue::Value(ArtifactValue::Int(credit_r)), ArgValue::Value(ArtifactValue::Int(5))]),
            cb_outpoint,
            cb_utxo.clone(),
            0,
        )
        .actor_output("budget_app::Budget", cb_out, binding(6, cb_covid), cb_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount);
    let mut tx = builder.build(&context).expect("swap_out_fee tx");
    let txid = preverify_and_submit("SWAP_OUT_FEE", &mut tx, vec![psm_utxo, auth_utxo, holder_utxo, s_utxo, ora_utxo, funding, cb_utxo], client).await;
    record_box("budget", cb_covid, txid, 5, cb_value, cb_extra);
    record_box("psm", psm_covid, txid, 0, psm_value_out, serde_json::json!({"ceiling": ceiling, "minted": minted - c, "spread": spread, "wired": true}));
    record_box("authority", kusd_covid, txid, 1, auth_value + holder_value - FEE, serde_json::json!({"amount": auth_amount + c, "ext": hex32(&gate.ext)}));
    record_box("surplus", surplus_covid, txid, 3, s_value_out, serde_json::json!({}));
    record_box("oracle", oracle_covid, txid, 4, oracle_value, oracle_extra.clone());
    remove_box("swap_holder");
    println!("*** LIVE SWAP_OUT_FEE: {c} cents burned, redeemer nets {payout}, SURPLUS +{fee} sompi ***");
}

/// Terminal close of a debt-free vault under the frozen family.
/// Env: VAULT_BOX (default "vault").
async fn close(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let vault_name = env_name("VAULT_BOX", "vault");
    let (oracle_covid, _, _, _) = box_info("oracle");
    let (kusd_covid, auth_outpoint, auth_value, auth_extra) = box_info("authority");
    let (vault_covid, vault_outpoint, vault_value, vault_extra) = box_info(&vault_name);
    let (surplus_covid_h, _, _, _) = box_info("surplus");
    let auth_amount = auth_extra["amount"].as_i64().unwrap();
    let (collateral, debt) = (vault_extra["collateral"].as_i64().unwrap(), vault_extra["debt"].as_i64().unwrap());
    assert_eq!(debt, 0, "close needs a debt-free vault");

    let deploy = keypair("deploy");
    let auth = kusd_state_map(auth_amount, xonly(&keypair("gov0")), 0x10, gate.ext.clone());
    let vault_in = vault_state_map(collateral, 0, kusd_covid.as_bytes().to_vec(), oracle_covid.as_bytes().to_vec(), surplus_covid_h.as_bytes().to_vec());

    let vault_utxo = builder.covenant_utxo("vault_app::Vault", vault_in.clone(), vault_value, 0, false, Some(vault_covid)).expect("vault utxo");
    let auth_utxo = builder.covenant_utxo("kusd_app::Kusd", auth.clone(), auth_value, 0, false, Some(kusd_covid)).expect("auth utxo");

    let release = vault_value - FEE;
    let emission_states = ArtifactValue::Array(vec![obj(auth.clone())]);
    let signer = deploy;
    let context = TxContext::new()
        .actor_input(
            "vault_app::Vault",
            vault_in,
            EntryCall::new("close").args_with(move |tx, input_idx| {
                vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &signer)))]
            }),
            vault_outpoint,
            vault_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            auth.clone(),
            EntryCall::new("emission").args_with(move |_tx, _idx| emission_args(emission_states.clone(), 0, false)),
            auth_outpoint,
            auth_utxo.clone(),
            0,
        )
        .actor_output("kusd_app::Kusd", auth, binding(1, kusd_covid), auth_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, release);
    let mut tx = builder.build(&context).expect("close tx");
    let txid = preverify_and_submit("CLOSE", &mut tx, vec![vault_utxo, auth_utxo], client).await;
    record_box("authority", kusd_covid, txid, 0, auth_value, auth_extra.clone());
    remove_box(&vault_name);
    println!("*** LIVE CLOSE: vault '{vault_name}' lineage TERMINATED, {release} sompi released to owner ***");
}

/// Re-state a deploy-owned holder box as borrow-enabled (amount-threshold 0)
/// owned by TO. Env: HOLDER_BOX (default "minted"), TO (default "user2").
async fn borrow_setup(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let box_name = env_name("HOLDER_BOX", "minted");
    let to_name = env_name("TO", "user2");
    let (kusd_covid, h_outpoint, h_value, h_extra) = box_info(&box_name);
    let amount = h_extra["amount"].as_i64().unwrap();
    let from_name = h_extra["owner"].as_str().unwrap().to_string();
    let from = keypair(&from_name);
    let to = keypair(&to_name);

    let h_in = kusd_state_map(amount, xonly(&from), 0x00, gate.ext.clone());
    let h_out = kusd_state_map_borrow(amount, xonly(&to), 0x01, vec![0u8; 32], gate.ext.clone());
    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", h_in.clone(), h_value, 0, false, Some(kusd_covid)).expect("holder utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let new_states = ArtifactValue::Array(vec![obj(h_out.clone())]);
    let signer = from;
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            h_in,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                let mut w = vec![0x00u8];
                w.extend_from_slice(&sign_input(tx, input_idx, &signer));
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
            }),
            h_outpoint,
            h_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("kusd_app::Kusd", h_out, binding(0, kusd_covid), h_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("borrow_setup tx");
    let txid = preverify_and_submit("BORROW_SETUP", &mut tx, vec![h_utxo, funding], client).await;
    record_box(&box_name, kusd_covid, txid, 0, h_value, serde_json::json!({"amount": amount, "owner": to_name, "borrow": "threshold0"}));
    println!("*** LIVE BORROW_SETUP: {amount}-cent box -> '{to_name}' with KCC-20 amount-threshold borrow policy ***");
}

/// Borrowed receive: pay PAY_CENTS from PAYER_BOX into the borrow-enabled
/// HOLDER_BOX WITHOUT its owner's signature (KCC-20 §5).
async fn borrow_pay(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let gate = live_gate();
    let box_name = env_name("HOLDER_BOX", "minted");
    let payer_name = env_name("PAYER_BOX", "swap_holder");
    let pay = env_i64("PAY_CENTS", 50);
    let (kusd_covid, h_outpoint, h_value, h_extra) = box_info(&box_name);
    let (_, p_outpoint, p_value, p_extra) = box_info(&payer_name);
    let amount = h_extra["amount"].as_i64().unwrap();
    let owner_name = h_extra["owner"].as_str().unwrap().to_string();
    let payer_amount = p_extra["amount"].as_i64().unwrap();
    let payer_owner = p_extra["owner"].as_str().unwrap().to_string();
    assert!(payer_amount > pay);

    let owner = keypair(&owner_name); // does NOT sign — borrow path
    let payer = keypair(&payer_owner);
    let h_in = kusd_state_map_borrow(amount, xonly(&owner), 0x01, vec![0u8; 32], gate.ext.clone());
    let h_out = kusd_state_map_borrow(amount + pay, xonly(&owner), 0x01, vec![0u8; 32], gate.ext.clone());
    let p_in = kusd_state_map(payer_amount, xonly(&payer), 0x00, gate.ext.clone());
    let p_out = kusd_state_map(payer_amount - pay, xonly(&payer), 0x00, gate.ext.clone());

    let h_utxo = builder.covenant_utxo("kusd_app::Kusd", h_in.clone(), h_value, 0, false, Some(kusd_covid)).expect("holder utxo");
    let p_utxo = builder.covenant_utxo("kusd_app::Kusd", p_in.clone(), p_value, 0, false, Some(kusd_covid)).expect("payer utxo");

    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let new_states = ArtifactValue::Array(vec![obj(h_out.clone()), obj(p_out.clone())]);
    let context = TxContext::new()
        .actor_input(
            "kusd_app::Kusd",
            h_in,
            EntryCall::new("transfer").args_with(move |_tx, _idx| {
                // PATH_BORROW + empty threshold payload: nobody signs for the leader
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(vec![0x01u8]))]
            }),
            h_outpoint,
            h_utxo.clone(),
            0,
        )
        .actor_input(
            "kusd_app::Kusd",
            p_in,
            EntryCall::new("transfer_delegator").args_with({
                let kp = payer;
                move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp)))]
            }),
            p_outpoint,
            p_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("kusd_app::Kusd", h_out, binding(0, kusd_covid), h_value)
        .actor_output("kusd_app::Kusd", p_out, binding(0, kusd_covid), p_value)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("borrow_pay tx");
    let txid = preverify_and_submit("BORROW_PAY", &mut tx, vec![h_utxo, p_utxo, funding], client).await;
    record_box(&box_name, kusd_covid, txid, 0, h_value, serde_json::json!({"amount": amount + pay, "owner": owner_name, "borrow": "threshold0"}));
    record_box(&payer_name, kusd_covid, txid, 1, p_value, serde_json::json!({"amount": payer_amount - pay, "owner": payer_owner}));
    println!("*** LIVE BORROWED RECEIVE: {pay} cents paid into '{box_name}' WITHOUT its owner's signature (KCC-20 borrow policy) ***");
}

/// Governance surplus withdrawal (2-of-3). Env: SPEND_AMOUNT (sompi).
async fn surplus_spend(client: &GrpcClient) {
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let (kusd_covid, _, _, _) = box_info("authority");
    let (surplus_covid, surplus_outpoint, surplus_value, _) = box_info("surplus");
    let amount = env_i64("SPEND_AMOUNT", 2_000_000);
    let s_in = surplus_state_map(vec![0u8; 32]);
    let s_value_out = (surplus_value as i64 - amount) as u64;

    let s_utxo = builder.covenant_utxo("surplus_app::Surplus", s_in.clone(), surplus_value, 0, false, Some(surplus_covid)).expect("surplus utxo");
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let change = funding.amount - FEE;
    let dest = xonly(&keypair("deploy"));
    let mut dest_spk = vec![0x20];
    dest_spk.extend_from_slice(&dest);
    dest_spk.push(0xac);

    let (ga, gb) = (keypair("gov0"), keypair("gov2"));
    let dest_arg = dest.clone();
    let context = TxContext::new()
        .actor_input(
            "surplus_app::Surplus",
            s_in.clone(),
            EntryCall::new("spend").args_with(move |tx, input_idx| {
                vec![
                    ArgValue::Value(ArtifactValue::Int(amount)),
                    ArgValue::Value(ArtifactValue::Bytes(dest_arg.clone())),
                    ArgValue::Value(ArtifactValue::Int(0)),
                    ArgValue::Value(ArtifactValue::Int(2)),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &ga))),
                    ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &gb))),
                ]
            }),
            surplus_outpoint,
            s_utxo.clone(),
            0,
        )
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .actor_output("surplus_app::Surplus", s_in, binding(0, surplus_covid), s_value_out)
        .output(kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, dest_spk), None, amount as u64)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, change);
    let mut tx = builder.build(&context).expect("surplus spend tx");
    let txid = preverify_and_submit("SURPLUS_SPEND", &mut tx, vec![s_utxo, funding], client).await;
    record_box("surplus", surplus_covid, txid, 0, s_value_out, serde_json::json!({}));
    println!("*** LIVE SURPLUS SPEND: governance withdrew {amount} sompi of protocol revenue (2-of-3) ***");
}

/// Self-payment that creates a freshly confirmed deploy UTXO: the next tx's
/// clock input then proves a current DAA score (the refresh clock reads the
/// funding input's CONFIRMATION time, not wall time).
async fn touch(client: &GrpcClient) {
    let (fund_outpoint, funding) = pick_funding(client, 2 * FEE).await;
    let runtime = protocol_runtime();
    let builder = TxBuilder::from_bundle(&runtime).expect("builder");
    let context = TxContext::new()
        .input(fund_outpoint, funding.clone(), p2pk_signer(keypair("deploy")), 0)
        .output(pay_to_address_script(&address(&keypair("deploy"))), None, funding.amount - FEE);
    let mut tx = builder.build(&context).expect("touch tx");
    preverify_and_submit("TOUCH", &mut tx, vec![funding], client).await;
}

#[tokio::main]
async fn main() {
    let stage = std::env::var("STAGE").unwrap_or_else(|_| "status".into());
    let client = rpc().await;
    match stage.as_str() {
        "status" => status(&client).await,
        "oracleboot" => oracle_bootstrap_json(),
        "psmboot" => psm_bootstrap_json(),
        "kusdboot" => kusd_bootstrap_json(),
        "oracle" => oracle_genesis(&client).await,
        "psm" => psm_genesis(&client).await,
        "authority" => authority_genesis(&client).await,
        "wire" => wire(&client).await,
        "vault" => vault_genesis(&client).await,
        "mint" => mint(&client).await,
        "swapin" => swap_in(&client).await,
        "swapout" => swap_out(&client).await,
        "transfer" => transfer(&client).await,
        "refresh" => refresh(&client).await,
        "adjust" => adjust(&client).await,
        "setceiling" => set_ceiling(&client).await,
        "repay" => repay(&client).await,
        "liquidate" => liquidate(&client).await,
        "rotate" => rotate(&client).await,
        "surplus" => surplus_genesis(&client).await,
        "budget" => budget_genesis(&client).await,
        "touch" => touch(&client).await,
        "setmember" => set_member(&client).await,
        "budgetwire" => budget_wire(&client).await,
        "setlimit" => budget_set_limit(&client).await,
        "freeze" => oracle_status(&client, "freeze").await,
        "settle" => oracle_status(&client, "settle").await,
        "surplusboot" => surplus_bootstrap_json(),
        "budgetboot" => budget_bootstrap_json(),
        "setparams" => set_ceiling(&client).await,
        "swapinfee" => swap_in_fee(&client).await,
        "swapoutfee" => swap_out_fee(&client).await,
        "close" => close(&client).await,
        "borrowsetup" => borrow_setup(&client).await,
        "borrowpay" => borrow_pay(&client).await,
        "surplusspend" => surplus_spend(&client).await,
        other => panic!("unknown STAGE '{other}'"),
    }
}

/// Per-refresh rate step, mirrored from oracle.ag: at least one unit once time has elapsed.
fn rate_step(p: i64, elapsed: i64, div: i64) -> i64 {
    let s = p * elapsed / div;
    if s < 1 && elapsed > 0 { 1 } else { s }
}
