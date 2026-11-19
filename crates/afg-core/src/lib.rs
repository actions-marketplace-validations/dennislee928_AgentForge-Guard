//! Policy schema, normalization and evaluation. This is the only component that makes authorization decisions (ADR 0002).

pub mod builtin;
pub mod conformance;
pub mod eval;
pub mod normalize;
pub mod paths;
pub mod policy;
pub mod schema;
pub mod shell;
pub mod validate;

pub use eval::{Decision, Engine, EvalRequest, ShellDecision};
pub use policy::{BackendKind, Effect, Policy};
