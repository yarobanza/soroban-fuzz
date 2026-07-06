# soroban-fuzz

Property-based fuzzing for [Soroban](https://soroban.stellar.org) smart
contracts — the missing `forge fuzz` / [Trident](https://ackee.xyz/trident/)
equivalent for the Stellar contract ecosystem.

## The gap

Soroban ships great unit-testing ergonomics (`#[test]` + a local sandbox
`Env`), but nothing that automatically hammers a contract with adversarial,
edge-case-biased inputs and checks that invariants like *"total supply never
changes on transfer"* survive. Every team currently hand-rolls a handful of
"reasonable" test cases — which is exactly the class of testing that misses
overflow, self-transfer, and re-entrancy-shaped bugs, because a human
choosing test inputs rarely picks `u128::MAX` or "transfer to yourself."

Security review capacity is the most commonly cited bottleneck for
RWA/stablecoin contracts scaling on Stellar. `soroban-fuzz` is an
"improve security by construction" tool: run it in CI, and a whole class of
storage-invariant and overflow/panic bugs gets caught before an auditor (or
an attacker) ever sees the contract.

## What's in this repo

- **`soroban-fuzz-core`** — the fuzzing engine. Generates random,
  edge-case-biased values shaped like Soroban's `Val` type space (`U32`,
  `I128`, `Symbol`, `Vec`, `Map`, `Address`, ...), drives random call
  sequences against a contract-under-test, catches panics, checks
  user-defined storage invariants after every call, and **shrinks** any
  failing sequence down to a minimal reproduction.
- **`soroban-fuzz-cli`** — a small CLI (`init` to scaffold a new fuzz
  target, `report` to pretty-print a saved failure report), modeled on the
  `cargo-fuzz` workflow: you write a target, this tool helps you run and
  inspect it.
- **`examples/token-contract`** — a worked example: a simplified
  mint/transfer/burn contract with **one intentionally injected bug** (a
  classic self-transfer double-credit), so running the fuzzer produces a
  real, reproducible finding instead of a "trust me it works" claim.

## Quickstart

```bash
git clone https://github.com/yarobanza/soroban-fuzz
cd soroban-fuzz
cargo run --release --bin fuzz_token -p token-contract-fuzz-example
```

Expect output like:

```
iterations run: 3354
failures found: 50

--- failure #1 (seed 2235605109413233710) ---
InvariantBroken { invariant: "sum(balances) == total_supply", reason: "sum(balances) = 2 != total_supply = 1" }
minimal repro:
  mint([Address("ADDR_1"), U128(1)])
  transfer([Address("ADDR_1"), Address("ADDR_1"), U128(1)])
```

That's the fuzzer finding a real bug — a self-transfer (`transfer` with
`from == to`) silently credits the recipient without the debit sticking —
and shrinking a random multi-call sequence down to the two calls that
actually matter. See `examples/token-contract/src/lib.rs` for the bug and
an explanation of why it's there.

A `fuzz_report.json` is written alongside the run; inspect it later (or in
CI) with:

```bash
cargo run --bin soroban-fuzz -- report fuzz_report.json
```

## Fuzzing your own contract

The engine has **no dependency on `soroban-sdk`** — that's deliberate, see
[`docs/INTEGRATION.md`](docs/INTEGRATION.md). You implement the
`FuzzContract` trait over an adapter that dispatches into your real
contract (via `soroban-sdk`'s test `Env`, native or wasm), describe your
invariants as closures, and run:

```bash
cargo run --bin soroban-fuzz -- init my_contract
# edit fuzz_targets/my_contract/main.rs, add it as a [[bin]], then:
cargo run --release --bin my_contract
```

## Architecture

```
soroban-fuzz-core/
  src/value.rs     ValueKind + SorobanValue: typed, edge-biased generation
  src/contract.rs  FuzzContract / Invariant traits
  src/runner.rs     FuzzRunner: random sequences, panic capture, shrinking
soroban-fuzz-cli/   init / report subcommands
examples/token-contract/
                    worked example + injected bug + fuzz target binary
docs/INTEGRATION.md real soroban-sdk contract wiring guide
```

## Status & roadmap

This is an MVP focused on single-contract fuzzing, matching the scope of
an SCF Build Award milestone plan:

- [x] Typed value generation matching Soroban's `Val` shape, with
      edge-case bias (0, 1, MAX, MAX-1, MIN)
- [x] Random multi-call sequence generation against a fresh contract
      instance per run
- [x] Panic capture + user-defined storage invariant checking after every
      call
- [x] Failure shrinking to a minimal reproducing call sequence
- [x] Worked example with an injected, fuzzer-found bug
- [ ] `soroban-sdk` `Env` adapter helper crate (reduce the integration
      guide's hand-written boilerplate to a derive macro)
- [ ] Corpus persistence + coverage-guided mutation (today's generation is
      purely random per call; coverage feedback would make deeper storage
      states reachable)
- [ ] Multi-contract fuzzing (cross-contract call sequences)
- [ ] GitHub Action for one-line CI integration

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
