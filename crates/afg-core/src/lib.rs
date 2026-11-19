//! Policy schema, normalization and evaluation. This is the only component that makes authorization decisions (ADR 0002).

pub mod policy;
pub mod schema;

pub use policy::Policy;
