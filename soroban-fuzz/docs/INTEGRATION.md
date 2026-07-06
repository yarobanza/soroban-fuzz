# Integrating a real Soroban contract

`soroban-fuzz-core` intentionally has **no dependency on `soroban-sdk`**.
That's a design choice, not a limitation left for later:

- `soroban-sdk` contracts compile to wasm32 and expect a host `Env`. Linking
  that into a fuzzing loop that also wants to run millions of fast, native,
  in-process iterations adds a lot of surface area (host mocking, wasm
  interpreter overhead, `Env`-per-iteration setup cost).
- The actual hard part of fuzzing — typed generation of Val-shaped inputs,
  running call sequences, catching panics, checking invariants, shrinking
  failures — is orthogonal to *how* a call gets dispatched.

So the engine works against anything that implements the `FuzzContract`
trait. The included example (`examples/token-contract`) implements it over
plain Rust structs to keep the repo buildable with zero SDK setup. To fuzz
a real Soroban contract, write a thin adapter:

```rust
use soroban_sdk::{Env, Address, testutils::Address as _};
use soroban_fuzz_core::{FuzzContract, CallOutcome, EntryPoint, SorobanValue, ValueKind};

pub struct MyContractAdapter {
    env: Env,
    contract_id: Address,
}

impl FuzzContract for MyContractAdapter {
    fn new_instance() -> Self {
        let env = Env::default();
        let contract_id = env.register_contract(None, MyContract);
        MyContractAdapter { env, contract_id }
    }

    fn entry_points(&self) -> Vec<EntryPoint> {
        vec![
            EntryPoint::new("transfer", vec![ValueKind::Address, ValueKind::Address, ValueKind::I128]),
            // ... one entry per public contract function you want fuzzed
        ]
    }

    fn call(&mut self, function: &str, args: &[SorobanValue]) -> CallOutcome {
        let client = MyContractClient::new(&self.env, &self.contract_id);
        match function {
            "transfer" => {
                let from = to_address(&self.env, &args[0]);
                let to = to_address(&self.env, &args[1]);
                let amount = to_i128(&args[2]);
                // client.try_transfer returns Result so a contract-level
                // rejection (panic_with_error!) doesn't need to unwind:
                match client.try_transfer(&from, &to, &amount) {
                    Ok(_) => CallOutcome::Ok(SorobanValue::Void),
                    Err(_) => CallOutcome::Rejected("rejected".into()),
                }
            }
            other => panic!("unmapped entry point: {other}"),
        }
    }
}
```

Key points:

1. **Prefer the generated `try_*` client methods** (soroban-sdk generates
   these alongside the panicking ones) so an intentional
   `panic_with_error!` for bad input shows up as `CallOutcome::Rejected`,
   not a `Panic` finding — the runner treats real traps (arithmetic
   overflow in `#[cfg(not(debug_assertions))]`... wait, in release Soroban
   contracts still trap on overflow by default) as findings, and expected
   rejections as normal control flow.
2. **Invariants read contract storage**, typically through a `try_*`
   getter (`total_supply`, `balance_of`, ...) called against the same
   `Env`/`contract_id` your adapter holds.
3. **Address generation**: `ValueKind::Address` produces a small pool of
   opaque string IDs (`ADDR_0`..`ADDR_3` by default) so the same actor
   plausibly reappears across calls in a sequence (self-transfers,
   double-spends, re-entrant patterns). Map each ID to a
   `Address::generate(&env)` you create once per `new_instance()` and
   cache in the adapter, so the same fuzz-level ID always resolves to the
   same real `Address` within one run.
4. **Numeric kinds** (`I128`/`U128`/etc.) are generated with a bias toward
   `0`, `1`, `MAX`, `MAX-1`, `MIN` — the boundary values where overflow and
   off-by-one bugs live. If your contract function takes an amount that
   should never be negative, use `ValueKind::U128`/`ValueKind::I128` and
   reject negative values inside `call` via `CallOutcome::Rejected` rather
   than filtering them out at generation time — feeding "invalid" inputs
   and confirming they're rejected (not silently accepted, not panicking)
   is itself a property worth checking.

## Running against a wasm build instead of native

If you'd rather fuzz the actual compiled `.wasm` (closer to what's
deployed) instead of the native contract code, swap `env.register_contract`
for `env.register_contract_wasm(None, WASM)` in `new_instance`. Everything
else in the adapter is unchanged — the fuzzing engine doesn't know or care
whether calls are dispatched natively or through the wasm host.
