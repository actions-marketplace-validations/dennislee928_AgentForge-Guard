//! Policy schema, normalization and evaluation. This is the only component that makes authorization decisions (ADR 0002).

pub mod normalize;
pub mod policy;
pub mod schema;
pub mod validate;

pub use policy::Policy;
