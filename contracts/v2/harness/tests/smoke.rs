// Task 1 smoke test: the argent-playground Counter app builds, its bump tx
// executes under the covenant engine, and the meter reports real numbers.

use argent_runtime::{EntryCall, TxBuilder, TxContext, args, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};
use kusd_v2_harness::{build_app_inline, demo_outpoint, meter};

const COUNTER_APP: &str = r#"
state CounterState {
    int count;
}

actor Counter owns CounterState {
    entry bump(int delta) emits next: Counter {
        CounterState next_state = {
            count: count + delta,
        };

        unrestricted(next.value);
        become next <- Counter(next_state);
    }
}

app CounterApp {
    actor Counter;
}
"#;

#[test]
fn counter_bump_executes_and_meters() {
    let artifact = build_app_inline("counter", COUNTER_APP);
    let builder = TxBuilder::new(&artifact).expect("tx builder");

    let initial = state! { count: 2 };
    let next = state! { count: 5 };
    let input_value = 1_000;
    let covenant_id = Hash::from_bytes([0x42; 32]);

    let input_utxo = builder
        .covenant_utxo("Counter", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("input utxo");
    let context = TxContext::new()
        .actor_input("Counter", initial, EntryCall::new("bump").args(args![3]), demo_outpoint(0x11, 0), input_utxo.clone(), 0)
        .actor_output("Counter", next, CovenantBinding::new(0, covenant_id), input_value);
    let mut tx = builder.build(&context).expect("build tx");

    let report = meter(&mut tx, vec![input_utxo]);
    println!("SMOKE: units={:?} compute_mass={} transient_mass={}", report.per_input_units, report.compute_mass, report.transient_mass);
    assert!(report.per_input_units[0] > 0);
    assert!(report.compute_mass > 0);
}
