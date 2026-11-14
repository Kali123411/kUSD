// Phase 4 Task 3: KCC-20 conformance vectors, driven by the vendored reference
// fixture (contracts/v2/vendor/kcc20/conformance.json, sha256
// 9b424c96ea0e0093cacfd98e3013fd5cbf93dd149cb27696acf288510133010b; KCC-20 per
// kaspanet/kccs kcc-0020.md as implemented by argent-lang/kcc20-reference —
// see vendor/kcc20/PROVENANCE.md) against kUSD's OWN compiled contract under
// the covenant engine.
//
// Signature policy (fixture "byte_string_format.signatures"): placeholder
// sigs/pubkeys are substituted with REAL keys wherever a case's outcome is not
// about the signature itself; the substitution preserves each case's semantic
// relationships (guards recomputed from the substituted key only where the
// fixture's own values were internally consistent).
//
// Declared kUSD deviations (also pinned by tests here and in kusd_token.rs):
//   D1 per-output value >= DUST (100M sompi, KIP-9 floor);
//   D2 owner_scheme 0x10 = supply authority (frozen under transfer);
//   D3 supply changes only via the gated `emission` entry (outside KCC-20).

use argent_runtime::{ArgValue, ArtifactValue, EntryCall, TxBuilder, TxContext, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kaspa_txscript::pay_to_script_hash_script;
use kusd_v2_harness::{
    actor_template_parts, build_app, demo_keypair, demo_outpoint, meter, meter_expect_err, sign_input,
};
use std::collections::BTreeMap;

const DUST: u64 = 100_000_000;
const COVID: [u8; 32] = [0x42; 32];

fn fixture() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vendor/kcc20/conformance.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vendored fixture readable")).expect("fixture parses")
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

/// Build a KusdState map from fixture-style fields.
fn kstate(amount: i64, owner: Vec<u8>, scheme: u8, borrow: u8, guard: Vec<u8>, ext: Vec<u8>) -> BTreeMap<String, ArtifactValue> {
    state! {
        amount: amount,
        owner: owner,
        owner_scheme: scheme,
        borrow_scheme: borrow,
        borrow_guard: guard,
        extension_commitment: ext,
    }
}

fn fixture_state(v: &serde_json::Value) -> BTreeMap<String, ArtifactValue> {
    kstate(
        v["amount"].as_i64().unwrap(),
        hex(v["owner_hex"].as_str().unwrap()),
        hex(v["owner_scheme_hex"].as_str().unwrap())[0],
        hex(v["borrow_scheme_hex"].as_str().unwrap())[0],
        hex(v["borrow_guard_hex"].as_str().unwrap()),
        hex(v["extension_commitment_hex"].as_str().unwrap()),
    )
}

fn obj(map: BTreeMap<String, ArtifactValue>) -> ArtifactValue {
    ArtifactValue::Object(map)
}

struct Built {
    tx: kaspa_consensus_core::tx::Transaction,
    entries: Vec<kaspa_consensus_core::tx::UtxoEntry>,
}

fn run_case(result: Result<Built, String>, expect_accept: bool, id: &str) {
    match (result, expect_accept) {
        (Ok(mut built), true) => {
            meter(&mut built.tx, built.entries);
            println!("CONFORMANCE {id}: accept ✓");
        }
        (Ok(mut built), false) => {
            let err = meter_expect_err(&mut built.tx, built.entries);
            println!("CONFORMANCE {id}: reject ✓ ({err})");
        }
        (Err(e), false) => println!("CONFORMANCE {id}: reject ✓ (builder: {e})"),
        (Err(e), true) => panic!("CONFORMANCE {id}: expected accept, build failed: {e}"),
    }
}

// --- 1. state record + encoding --------------------------------------------------

#[test]
fn state_record_layout_and_encoding_match() {
    let f = fixture();
    let rec = &f["state_record"];
    assert_eq!(rec["field_types"].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect::<Vec<_>>(), vec![
        "int", "byte[32]", "byte", "byte", "byte[32]", "byte[32]"
    ]);

    // The binding check: a kUSD covenant box whose state is the fixture's
    // state must carry EXACTLY the P2SH of prefix ++ fixture-encoded ++ suffix.
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let (prefix, suffix, _hash) = actor_template_parts(&artifact, "Kusd");
    let builder = TxBuilder::new(&artifact).expect("tx builder");

    let enc = &f["state_encoding"];
    let st = fixture_state(&enc["state"]);
    let utxo = builder.covenant_utxo("Kusd", st, DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");

    let encoded = hex(enc["encoded_hex"].as_str().unwrap());
    assert_eq!(encoded.len() as i64, rec["encoded_state_length"].as_i64().unwrap(), "fixture self-consistency");
    let mut script = prefix.clone();
    script.extend_from_slice(&encoded);
    script.extend_from_slice(&suffix);
    let expected_spk = pay_to_script_hash_script(&script);
    assert_eq!(
        utxo.script_public_key, expected_spk,
        "kUSD's on-chain state encoding must equal the KCC-20 fixture encoding"
    );
    // per-field encodings compose to the whole
    let joined: Vec<u8> = enc["encoded_fields_hex"].as_array().unwrap().iter().flat_map(|s| hex(s.as_str().unwrap())).collect();
    assert_eq!(joined, encoded);
    println!("CONFORMANCE state-encoding: byte-exact ✓ (len {})", encoded.len());
}

// --- 2. dispatch tags + transfer argument encoding -------------------------------

#[test]
fn dispatch_tags_and_argument_encoding_match() {
    let f = fixture();
    let artifact = build_app("kusd", "../ag/kusd.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");

    // Build the EXACT transfer of the transfer_arguments vector (leader = the
    // standard_transfer common state, outputs = the vector's next_states),
    // with the owner substituted by a real key so the tx verifies.
    let ta = &f["transfer_arguments"];
    let common = &f["standard_transfer"]["common"];
    let leader_kp = demo_keypair(1);
    let mut leader = fixture_state(&common["leader_state"]);
    leader.insert("owner".into(), ArtifactValue::Bytes(xonly(1)));

    let outs: Vec<BTreeMap<String, ArtifactValue>> = ta["next_states"].as_array().unwrap().iter().map(fixture_state).collect();
    let utxo = builder.covenant_utxo("Kusd", leader.clone(), 3 * DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");
    let new_states = ArtifactValue::Array(outs.iter().cloned().map(obj).collect());

    let mut context = TxContext::new().actor_input(
        "Kusd",
        leader,
        EntryCall::new("transfer").args_with(move |tx, input_idx| {
            let mut w = vec![0x00];
            w.extend_from_slice(&sign_input(tx, input_idx, &leader_kp));
            vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
        }),
        demo_outpoint(0x31, 0),
        utxo.clone(),
        0,
    );
    for (j, out) in outs.into_iter().enumerate() {
        context = context.actor_output("Kusd", out, CovenantBinding::new(0, Hash::from_bytes(COVID)), DUST + j as u64);
    }
    let mut tx = builder.build(&context).expect("vector transfer builds");

    let sig_script = to_hex(&tx.inputs[0].signature_script);
    // dispatch tags: structural function signatures, so kUSD's identical
    // layout must produce the reference's exact tags
    for entry in f["dispatch"].as_array().unwrap() {
        let tag = entry["dispatch_tag_hex"].as_str().unwrap();
        if entry["entrypoint"] == "transfer" {
            assert!(sig_script.contains(tag), "leader sigScript must carry the KCC-20 transfer dispatch tag {tag}");
        }
        println!("CONFORMANCE dispatch {}: tag {tag}", entry["entrypoint"]);
    }
    // grouped next_states field pushes appear verbatim in the sigScript
    for push in ta["grouped_field_pushes_hex"].as_array().unwrap() {
        let p = push.as_str().unwrap();
        assert!(sig_script.contains(p), "sigScript must carry grouped field push {p}");
    }
    assert!(sig_script.contains(ta["dispatch_tag_push_hex"].as_str().unwrap()));
    meter(&mut tx, vec![utxo]);
    println!("CONFORMANCE transfer-arguments: encoding byte-exact in sigScript ✓");
}

// --- 3. standard transfer cases ---------------------------------------------------

#[test]
fn standard_transfer_cases() {
    let f = fixture();
    let st = &f["standard_transfer"];
    let common = &st["common"];
    let base_outs = f["transfer_arguments"]["next_states"].as_array().unwrap().clone();

    for case in st["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let expect_accept = case["result"] == "accept";

        let artifact = build_app("kusd", "../ag/kusd.ag");
        let builder = TxBuilder::new(&artifact).expect("tx builder");
        let leader_kp = demo_keypair(1);
        let mut leader = fixture_state(&common["leader_state"]);
        leader.insert("owner".into(), ArtifactValue::Bytes(xonly(1)));

        // apply overrides
        let mut outs: Vec<BTreeMap<String, ArtifactValue>> = base_outs.iter().map(fixture_state).collect();
        if let Some(amounts) = case["next_state_amounts"].as_array() {
            // may lengthen the output list (over-max case shrinks inputs side instead)
            while outs.len() < amounts.len() {
                outs.push(outs[outs.len() - 1].clone());
            }
            outs.truncate(amounts.len());
            for (o, a) in outs.iter_mut().zip(amounts) {
                o.insert("amount".into(), ArtifactValue::Int(a.as_i64().unwrap()));
            }
        }
        if let Some(schemes) = case["next_state_owner_schemes_hex"].as_array() {
            for (o, s) in outs.iter_mut().zip(schemes) {
                o.insert("owner_scheme".into(), ArtifactValue::Byte(hex(s.as_str().unwrap())[0]));
            }
        }
        if let Some(exts) = case["next_state_extension_commitments_hex"].as_array() {
            for (o, e) in outs.iter_mut().zip(exts) {
                o.insert("extension_commitment".into(), ArtifactValue::Bytes(hex(e.as_str().unwrap())));
            }
        }
        let witness_override = case["witness_hex"].as_str().map(hex);
        let delegate_amounts: Vec<i64> =
            case["delegate_amounts"].as_array().unwrap_or(common["delegate_amounts"].as_array().unwrap()).iter().map(|a| a.as_i64().unwrap()).collect();

        let leader_utxo = builder.covenant_utxo("Kusd", leader.clone(), 5 * DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");
        let new_states = ArtifactValue::Array(outs.iter().cloned().map(obj).collect());
        let mut context = TxContext::new().actor_input(
            "Kusd",
            leader.clone(),
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                let w = witness_override.clone().unwrap_or_else(|| {
                    let mut w = vec![0x00];
                    w.extend_from_slice(&sign_input(tx, input_idx, &leader_kp));
                    w
                });
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
            }),
            demo_outpoint(0x32, 0),
            leader_utxo.clone(),
            0,
        );
        let mut entries = vec![leader_utxo];
        for (i, amt) in delegate_amounts.iter().enumerate() {
            let k = 2 + i as u8;
            let d_state = kstate(*amt, xonly(k), 0x00, 0x00, vec![0u8; 32], hex(common["leader_state"]["extension_commitment_hex"].as_str().unwrap()));
            let d_utxo = builder.covenant_utxo("Kusd", d_state.clone(), 2 * DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("delegate utxo");
            let kp = demo_keypair(k);
            context = context.actor_input(
                "Kusd",
                d_state,
                EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &kp)))]),
                demo_outpoint(0x33 + i as u8, 0),
                d_utxo.clone(),
                0,
            );
            entries.push(d_utxo);
        }
        for (j, out) in outs.into_iter().enumerate() {
            context = context.actor_output("Kusd", out, CovenantBinding::new(0, Hash::from_bytes(COVID)), DUST + j as u64);
        }
        let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries });
        run_case(result, expect_accept, id);
    }
}

// --- 4. owner witness layouts (live acceptance per scheme) ------------------------

#[test]
fn owner_witness_cases() {
    let f = fixture();
    // fixture layout lengths (path byte + payload for the leader)
    for w in f["owner_witness"].as_array().unwrap() {
        let bytes = hex(w["witness_hex"].as_str().unwrap());
        assert_eq!(bytes.len() as i64, w["length"].as_i64().unwrap(), "fixture self-consistency");
    }

    // live acceptance: a 1-in/1-out transfer per owner scheme with a REAL
    // witness of exactly the fixture's layout
    let secp = secp256k1::Secp256k1::new();
    for scheme in [0x00u8, 0x01, 0x02, 0x03, 0x04] {
        let artifact = build_app("kusd", "../ag/kusd.ag");
        let builder = TxBuilder::new(&artifact).expect("tx builder");
        let kp = demo_keypair(1);
        let xo = xonly(1);
        let compressed = kp.public_key().serialize().to_vec();
        let redeem: Vec<u8> = vec![0x51]; // OP_TRUE redeem for the P2SH scheme
        let p2sh_spk = pay_to_script_hash_script(&redeem);
        let p2sh_hash = p2sh_spk.script()[2..34].to_vec();

        let owner: Vec<u8> = match scheme {
            0x00 => xo.clone(),
            0x01 => blake3::hash(&xo).as_bytes().to_vec(),
            0x02 => blake3::hash(&compressed).as_bytes().to_vec(),
            0x03 => p2sh_hash.clone(),
            0x04 => COVID.to_vec(), // covenant-id: the kusd group itself co-spends
            _ => unreachable!(),
        };
        let leader = kstate(700, owner.clone(), scheme, 0x00, vec![0u8; 32], vec![0u8; 32]);
        let out = kstate(700, xo.clone(), 0x00, 0x00, vec![0u8; 32], vec![0u8; 32]);
        let leader_utxo = builder.covenant_utxo("Kusd", leader.clone(), 2 * DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");
        let new_states = ArtifactValue::Array(vec![obj(out.clone())]);
        let (kp_w, compressed_w, secp_w) = (kp, compressed.clone(), secp.clone());
        let mut context = TxContext::new().actor_input(
            "Kusd",
            leader,
            EntryCall::new("transfer").args_with(move |tx, input_idx| {
                let mut w = vec![0x00u8]; // PATH_NORMAL
                match scheme {
                    0x00 => w.extend_from_slice(&sign_input(tx, input_idx, &kp_w)),
                    0x01 => {
                        w.extend_from_slice(&kp_w.x_only_public_key().0.serialize());
                        w.extend_from_slice(&sign_input(tx, input_idx, &kp_w));
                    }
                    0x02 => {
                        use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash};
                        use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
                        let reused = SigHashReusedValuesUnsync::new();
                        let hash = calc_ecdsa_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
                        let msg = secp256k1::Message::from_digest(hash.as_bytes());
                        let sig = secp_w.sign_ecdsa(&msg, &kp_w.secret_key());
                        w.extend_from_slice(&compressed_w);
                        w.extend_from_slice(&sig.serialize_compact());
                        w.push(SIG_HASH_ALL.to_u8());
                    }
                    0x03 => w.push(0x01), // the P2SH authority input sits at index 1
                    0x04 => {}            // empty payload: OpCovInputCount(owner) > 0
                    _ => unreachable!(),
                }
                vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
            }),
            demo_outpoint(0x40 + scheme, 0),
            leader_utxo.clone(),
            0,
        );
        let mut entries = vec![leader_utxo];
        if scheme == 0x03 {
            // co-spend a P2SH utxo whose hash is the owner; reveal OP_TRUE
            let utxo = kaspa_consensus_core::tx::UtxoEntry::new(DUST, p2sh_spk.clone(), 0, false, None);
            context = context.input(demo_outpoint(0x50, 0), utxo.clone(), vec![0x01, 0x51], 0);
            entries.push(utxo);
        }
        context = context.actor_output("Kusd", out, CovenantBinding::new(0, Hash::from_bytes(COVID)), 2 * DUST);
        let mut tx = builder.build(&context).unwrap_or_else(|e| panic!("owner scheme {scheme:#04x} transfer builds: {e}"));
        meter(&mut tx, entries);
        println!("CONFORMANCE owner-witness {scheme:#04x}: live accept ✓");
    }
}

// --- 5. borrowed receive cases ----------------------------------------------------

#[test]
fn borrowed_receive_cases() {
    let f = fixture();
    let br = &f["borrowed_receive"];
    let common = &br["common"];
    let ext = hex(common["extension_commitment_hex"].as_str().unwrap());
    let leader_amount = common["leader_amount"].as_i64().unwrap();
    // common owner scheme is 0x01 (p2pkh-schnorr): the borrow path never
    // authorizes the owner, so the placeholder owner stays as-is
    let owner = hex(common["owner_hex"].as_str().unwrap());
    let owner_scheme = hex(common["owner_scheme_hex"].as_str().unwrap())[0];

    for case in br["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap().to_string();
        let expect_accept = case["result"] == "accept";
        let borrow_scheme = hex(case["borrow_scheme_hex"].as_str().unwrap())[0];
        let mut leader_guard = hex(case["leader_borrow_guard_hex"].as_str().unwrap());
        let mut successor_guard = hex(case["successor_borrow_guard_hex"].as_str().unwrap());
        let successor_amount = case["successor_amount"].as_i64().unwrap();
        let mut witness = hex(case["witness_hex"].as_str().unwrap());
        let successor_owner = case["successor_owner_hex"].as_str().map(hex).unwrap_or_else(|| owner.clone());
        let leader_value = case["leader_kas_value_sompi"].as_u64().map(|v| v.max(DUST + 50_000_000)).unwrap_or(2 * DUST);
        let successor_value = if case["successor_kas_value_sompi"].is_u64() {
            // preserve the case's value RELATION (decrease) above the DUST floor
            let lv = case["leader_kas_value_sompi"].as_u64().unwrap();
            let sv = case["successor_kas_value_sompi"].as_u64().unwrap();
            if sv < lv { leader_value - (lv - sv) } else { leader_value + (sv - lv) }
        } else {
            leader_value
        };

        // real-key substitution for signature-bearing schemes
        let needs_real_sig = borrow_scheme == 0x03 && case["revealed_link_hash_hex"].is_null();
        if needs_real_sig {
            // witness = path ++ next_guard(32) ++ pk(32) ++ sig(65): keep the
            // fixture's next_guard, substitute pk, recompute guards that were
            // internally consistent with the placeholder pk
            let next_guard = witness[1..33].to_vec();
            let pk_real = xonly(9);
            let fixture_pk = witness[33..65].to_vec();
            let mut pre = next_guard.clone();
            pre.extend_from_slice(&fixture_pk);
            let consistent: Vec<u8> = blake3::hash(&pre).as_bytes().to_vec();
            let mut pre_real = next_guard.clone();
            pre_real.extend_from_slice(&pk_real);
            let real_guard: Vec<u8> = blake3::hash(&pre_real).as_bytes().to_vec();
            if leader_guard == consistent {
                leader_guard = real_guard.clone();
            }
            if successor_guard == consistent {
                successor_guard = real_guard;
            }
            witness = witness[..33].to_vec();
            witness.extend_from_slice(&pk_real);
            // sig appended inside the closure (needs the sighash)
        }

        let artifact = build_app("kusd", "../ag/kusd.ag");
        let builder = TxBuilder::new(&artifact).expect("tx builder");
        let leader = kstate(leader_amount, owner.clone(), owner_scheme, borrow_scheme, leader_guard, ext.clone());
        let payer_amount = (successor_amount - leader_amount).max(1) + 100;
        let payer = kstate(payer_amount, xonly(2), 0x00, 0x00, vec![0u8; 32], ext.clone());
        let out0 = kstate(successor_amount, successor_owner, owner_scheme, borrow_scheme, successor_guard, ext.clone());
        let out1 = kstate(payer_amount - (successor_amount - leader_amount), xonly(2), 0x00, 0x00, vec![0u8; 32], ext.clone());

        let leader_utxo = builder.covenant_utxo("Kusd", leader.clone(), leader_value, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");
        let payer_utxo = builder.covenant_utxo("Kusd", payer.clone(), 2 * DUST, 0, false, Some(Hash::from_bytes(COVID))).expect("utxo");
        let new_states = ArtifactValue::Array(vec![obj(out0.clone()), obj(out1.clone())]);
        let (k_payer, w_base) = (demo_keypair(2), witness.clone());
        let context = TxContext::new()
            .actor_input(
                "Kusd",
                leader,
                EntryCall::new("transfer").args_with(move |tx, input_idx| {
                    let mut w = w_base.clone();
                    if needs_real_sig {
                        w.extend_from_slice(&sign_input(tx, input_idx, &demo_keypair(9)));
                    }
                    vec![ArgValue::Value(new_states.clone()), ArgValue::Value(ArtifactValue::Bytes(w))]
                }),
                demo_outpoint(0x60, 0),
                leader_utxo.clone(),
                0,
            )
            .actor_input(
                "Kusd",
                payer,
                EntryCall::new("transfer_delegator").args_with(move |tx, input_idx| vec![ArgValue::Value(ArtifactValue::Bytes(sign_input(tx, input_idx, &k_payer)))]),
                demo_outpoint(0x61, 0),
                payer_utxo.clone(),
                0,
            )
            .actor_output("Kusd", out0, CovenantBinding::new(0, Hash::from_bytes(COVID)), successor_value)
            .actor_output("Kusd", out1, CovenantBinding::new(0, Hash::from_bytes(COVID)), 2 * DUST);
        let result = builder.build(&context).map_err(|e| e.to_string()).map(|tx| Built { tx, entries: vec![leader_utxo, payer_utxo] });
        run_case(result, expect_accept, &id);
    }
}

// --- 6. hash-chain vectors ---------------------------------------------------------

#[test]
fn hash_chain_vectors() {
    let f = fixture();
    let hc = &f["hash_chain"];
    let mut x = hex(hc["x_0_hex"].as_str().unwrap());
    for link in hc["links"].as_array().unwrap() {
        let pk = hex(link["pubkey_hex"].as_str().unwrap());
        let mut pre = x.clone();
        pre.extend_from_slice(&pk);
        x = blake3::hash(&pre).as_bytes().to_vec();
        assert_eq!(to_hex(&x), link["x_hex"].as_str().unwrap(), "link {} chains", link["i"]);
    }
    assert_eq!(to_hex(&x), hc["initial_borrow_guard_hex"].as_str().unwrap(), "initial guard = last link");
    println!("CONFORMANCE hash-chain: {} links verified ✓", hc["links"].as_array().unwrap().len());
}
