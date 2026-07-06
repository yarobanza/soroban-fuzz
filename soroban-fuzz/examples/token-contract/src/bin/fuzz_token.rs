use soroban_fuzz_core::{FnInvariant, FuzzConfig, FuzzContract, FuzzRunner};
use token_contract_fuzz_example::SimpleToken;

fn main() {
    let config = FuzzConfig {
        iterations: 20_000,
        min_calls_per_run: 1,
        max_calls_per_run: 6,
        max_depth: 3,
        seed: None,
    };

    let entry_points = SimpleToken::default().entry_points();

    let runner = FuzzRunner::<SimpleToken>::new(config).with_invariant(Box::new(FnInvariant::new(
        "sum(balances) == total_supply",
        |c: &SimpleToken| c.sum_balances_matches_supply(),
    )));

    let report = runner.run(&entry_points);

    println!("iterations run: {}", report.iterations_run);
    println!("failures found: {}", report.failures.len());

    for (i, failure) in report.failures.iter().enumerate() {
        println!("\n--- failure #{} (seed {}) ---", i + 1, failure.seed);
        println!("{:?}", failure.kind);
        println!("minimal repro:");
        for call in &failure.repro {
            println!("  {}({:?})", call.function, call.args);
        }
    }

    // Save the raw report so it can be inspected later with
    // `soroban-fuzz report fuzz_report.json`, or attached to a bug report /
    // CI artifact.
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        let _ = std::fs::write("fuzz_report.json", json);
    }

    if !report.is_clean() {
        std::process::exit(1);
    }
}
