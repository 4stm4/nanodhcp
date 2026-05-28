//! Leases: model, persistent store, allocation policy.

pub mod allocator;
pub mod model;
pub mod store;

pub use store::LeaseStore;
