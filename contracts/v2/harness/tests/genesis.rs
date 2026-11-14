// Phase 2 Task 5: the genesis path, verified locally — an Oracle genesis tx
// built through the runtime executes under the covenant engine, and its
// covenant id is derived the same way the node derives it. The deploy runbook
// (contracts/v2/deploy/README.md) cross-checks this covid against
// `argentc genesis compose/verify`.

use argent_runtime::{CovenantOutput, TxBuilder, TxContext, state};
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};
use kusd_v2_harness::{build_app, demo_keypair, demo_outpoint, meter};

const ORACLE_VALUE: u64 = 100_000_000;

fn xonly(byte: u8) -> Vec<u8> {
    demo_keypair(byte).x_only_public_key().0.serialize().to_vec()
}

#[test]
fn oracle_genesis_builds_and_meters() {
    let artifact = build_app("oracle", "../ag/oracle.ag");
    let builder = TxBuilder::new(&artifact).expect("tx builder");

    let initial = kusd_v2_harness::oracle_state_v2(4_000);
    // OP_TRUE funding input (the badge-demo idiom; on TN10 this is a real
    // funded outpoint and the runbook's deploy key signs it)
    let funding = UtxoEntry::new(ORACLE_VALUE, ScriptPublicKey::from_vec(0, vec![0x51]), 0, false, None);

    let context = TxContext::new()
        .input(demo_outpoint(0xBB, 0), funding.clone(), Vec::new(), 0)
        .actor_genesis_output(0, "launch::oracle", "Oracle", initial, ORACLE_VALUE);
    let mut tx = builder.build(&context).expect("genesis tx builds");
    let root = CovenantOutput::from_tx(&tx, 0).expect("covenant output");
    println!("ORACLE-GENESIS: covid={} outpoint={:?}", root.covenant_id, root.outpoint);

    let report = meter(&mut tx, vec![funding]);
    println!("ORACLE-GENESIS: units={:?} compute_mass={}", report.per_input_units, report.compute_mass);
    assert_ne!(root.covenant_id.as_bytes(), [0u8; 32]);
}

#[test]
fn print_member_keys_for_runbook() {
    // keeps the deploy runbook's bootstrap example in sync with the test keys
    println!("m0={:?}", xonly(10));
    println!("m1={:?}", xonly(11));
    println!("m2={:?}", xonly(12));
}
