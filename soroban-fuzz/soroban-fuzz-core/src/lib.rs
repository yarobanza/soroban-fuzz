//! soroban-fuzz-core: property-based fuzzing engine for Soroban contracts.
//!
//! Three pieces:
//! - [`value`]: a `SorobanValue`/`ValueKind` model mirroring Soroban's `Val`
//!   space, with typed random generation biased toward numeric edge cases.
//! - [`contract`]: the `FuzzContract` trait your contract adapter
//!   implements, plus the `Invariant` trait for storage/state properties.
//! - [`runner`]: `FuzzRunner`, which drives random call sequences against
//!   fresh contract instances, catches panics, checks invariants after
//!   every call, and shrinks failing sequences to a minimal repro.

pub mod contract;
pub mod runner;
pub mod value;

pub use contract::{CallOutcome, EntryPoint, FnInvariant, FuzzContract, Invariant};
pub use runner::{FailureKind, Failure, FuzzConfig, FuzzReport, FuzzRunner, RecordedCall};
pub use value::{SorobanValue, ValueKind};
