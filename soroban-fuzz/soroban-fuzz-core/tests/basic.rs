use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use soroban_fuzz_core::{
    CallOutcome, EntryPoint, FnInvariant, FuzzConfig, FuzzContract, FuzzRunner, SorobanValue,
    ValueKind,
};

#[test]
fn value_generation_respects_kind_shape() {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    for _ in 0..200 {
        match SorobanValue::arbitrary(&mut rng, &ValueKind::Symbol, 3) {
            SorobanValue::Symbol(s) => assert!(s.len() <= 32 && !s.is_empty()),
            other => panic!("expected Symbol, got {other:?}"),
        }
        match SorobanValue::arbitrary(
            &mut rng,
            &ValueKind::Vec(Box::new(ValueKind::U32), 5),
            3,
        ) {
            SorobanValue::Vec(v) => assert!(v.len() <= 5),
            other => panic!("expected Vec, got {other:?}"),
        }
    }
}

#[test]
fn depth_limit_prevents_unbounded_recursion() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let kind = ValueKind::Vec(Box::new(ValueKind::Vec(Box::new(ValueKind::U32), 3)), 3);
    // depth 0 must bottom out immediately regardless of nested max lengths.
    match SorobanValue::arbitrary(&mut rng, &kind, 0) {
        SorobanValue::Vec(v) => assert!(v.is_empty()),
        other => panic!("expected empty Vec at depth 0, got {other:?}"),
    }
}

/// A contract with an obvious, always-reachable bug: calling "boom" with
/// the exact value 42 panics. Used to check the runner actually detects
/// panics and shrinks the reproducing call sequence down to just that call.
struct BoomContract;

impl FuzzContract for BoomContract {
    fn new_instance() -> Self {
        BoomContract
    }
    fn entry_points(&self) -> Vec<EntryPoint> {
        vec![EntryPoint::new("boom", vec![ValueKind::U32])]
    }
    fn call(&mut self, function: &str, args: &[SorobanValue]) -> CallOutcome {
        assert_eq!(function, "boom");
        // 0 is one of the biased edge values `arbitrary` favors, so this is
        // reachable quickly without needing millions of iterations.
        if let SorobanValue::U32(0) = args[0] {
            panic!("boom hit 0");
        }
        CallOutcome::Ok(SorobanValue::Void)
    }
}

#[test]
fn runner_finds_and_shrinks_panic() {
    let config = FuzzConfig {
        iterations: 5_000,
        min_calls_per_run: 3,
        max_calls_per_run: 6,
        max_depth: 2,
        seed: Some(7),
    };
    let entry_points = BoomContract.entry_points();
    let runner = FuzzRunner::<BoomContract>::new(config);
    let report = runner.run(&entry_points);

    assert!(!report.is_clean(), "expected the fuzzer to find the panic");
    let failure = &report.failures[0];
    // Shrinking should reduce to exactly the one call that panics.
    assert_eq!(failure.repro.len(), 1);
    assert_eq!(failure.repro[0].function, "boom");
    assert_eq!(failure.repro[0].args[0], SorobanValue::U32(0));
}

/// A contract whose invariant ("counter never exceeds 100") is violated by
/// an "add" call - checks invariant violations (not just panics) are
/// caught and shrunk too.
struct CounterContract {
    value: u32,
}
impl FuzzContract for CounterContract {
    fn new_instance() -> Self {
        CounterContract { value: 0 }
    }
    fn entry_points(&self) -> Vec<EntryPoint> {
        vec![EntryPoint::new("add", vec![ValueKind::U32])]
    }
    fn call(&mut self, function: &str, args: &[SorobanValue]) -> CallOutcome {
        assert_eq!(function, "add");
        if let SorobanValue::U32(n) = args[0] {
            self.value = self.value.wrapping_add(n % 200);
        }
        CallOutcome::Ok(SorobanValue::Void)
    }
}

#[test]
fn runner_finds_invariant_violation() {
    let config = FuzzConfig {
        iterations: 5_000,
        min_calls_per_run: 1,
        max_calls_per_run: 4,
        max_depth: 1,
        seed: Some(3),
    };
    let entry_points = CounterContract::new_instance().entry_points();
    let runner = FuzzRunner::<CounterContract>::new(config).with_invariant(Box::new(
        FnInvariant::new("value <= 100", |c: &CounterContract| {
            if c.value <= 100 {
                Ok(())
            } else {
                Err(format!("value {} exceeds 100", c.value))
            }
        }),
    ));
    let report = runner.run(&entry_points);
    assert!(!report.is_clean());
}
