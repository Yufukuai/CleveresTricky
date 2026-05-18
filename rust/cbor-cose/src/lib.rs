//! Memory-safe CBOR/COSE encoder for CleveresTricky RKP attestation spoofing.
//!
//! Implements RFC 8949 (CBOR) canonical encoding and COSE_Mac0 structures
//! required for Android Remote Key Provisioning (RKP) operations.
//!
//! This Rust implementation mirrors the behavior of the Java `CborEncoder`
//! in `service/src/main/java/cleveres/tricky/cleverestech/util/CborEncoder.java`
//! while providing memory safety guarantees through Rust's borrow checker.
//!
//! # Architecture: Zygisk → C++ entry → Rust core
//!
//! The C++ `binder_interceptor` is loaded via Zygisk/ptrace injection and remains
//! the entry point. It calls into this Rust library through the C FFI functions
//! exposed in the [`ffi`] module for all CBOR encoding and COSE operations.

pub mod bcc;
pub mod binder_parser;
pub mod cbor;
pub mod cose;
pub mod ffi;
pub mod fingerprint;
pub mod properties;
pub mod utils;

pub mod race_engine;

pub mod play_integrity;
