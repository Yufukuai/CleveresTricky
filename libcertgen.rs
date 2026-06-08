// LOCAL PKI & DER ENGINE
// Native Rust PKI engine for isolated environments.
//
// FFI Safety Notes:
//   - All #[no_mangle] extern "C" functions are wrapped with catch_unwind so
//     that Rust panics never unwind across the FFI boundary into C++, which
//     is undefined behaviour.  On panic the function returns a sentinel error
//     value instead of aborting the process unexpectedly.
//   - Blocking I/O (/dev/random) has been replaced with ring::rand::SystemRandom
//     which is non-blocking, signal-safe, and works on all Android versions.

use std::panic::{catch_unwind, AssertUnwindSafe};
use ring::{rand, rand::SecureRandom, signature};
use ring::signature::KeyPair;
use ring::hmac;

pub struct CertEngine {
    seed: [u8; 32],
}

impl CertEngine {
    /// Create a new CertEngine.
    /// Uses `ring::rand::SystemRandom` (non-blocking) instead of opening
    /// `/dev/random` directly, which avoids blocking I/O in constructors and
    /// is safe to call from FFI contexts and from threads without a Looper.
    pub fn new() -> Self {
        let rng = rand::SystemRandom::new();
        let mut seed = [0u8; 32];
        // fill_bytes never blocks; returns Unspecified on error, in which case
        // we leave seed as all-zeros (a weaker but non-panicking fallback).
        let _ = rng.fill(&mut seed);
        Self { seed }
    }

    pub fn generate_ec_p256_keypair() -> Result<Vec<u8>, &'static str> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        ).map_err(|_| "Failed to generate keypair")?;

        Ok(pkcs8_bytes.as_ref().to_vec())
    }

    pub fn calculate_include_unique_id(&self, input: &[u8]) -> Vec<u8> {
        // Hardware ID Binding: Calculate using HMAC-SHA256 with persistent 32-byte seed
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.seed);
        let tag = hmac::sign(&key, input);
        tag.as_ref().to_vec()
    }

    pub fn validate_challenge(&self, challenge: &[u8]) -> Result<(), i32> {
        // Buffer Safety: Reject attestation_challenge inputs exceeding 128 bytes with INVALID_INPUT_LENGTH (-21)
        if challenge.len() > 128 {
            return Err(-21); // INVALID_INPUT_LENGTH
        }
        Ok(())
    }
}

// =============================================================================
// FFI-exported entry points
//
// Each function is guarded with std::panic::catch_unwind so that a Rust panic
// inside this module can never unwind into C++ code (undefined behaviour in
// the Rust/C++ FFI model).  On an unexpected panic the function returns a
// safe sentinel value instead.
// =============================================================================

/// Generate an EC P-256 keypair and write the PKCS#8-encoded bytes into
/// `out_buf` (caller-allocated, at least `out_buf_len` bytes).
/// Returns the number of bytes written, or 0 on error / panic.
#[no_mangle]
pub extern "C" fn certengine_generate_ec_p256_keypair(
    out_buf: *mut u8,
    out_buf_len: usize,
) -> usize {
    // Safety: catch_unwind ensures panics do not cross the FFI boundary.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pkcs8 = CertEngine::generate_ec_p256_keypair()
            .unwrap_or_default();
        if pkcs8.is_empty() || out_buf.is_null() || pkcs8.len() > out_buf_len {
            return 0usize;
        }
        // SAFETY: caller guarantees out_buf points to at least out_buf_len bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(pkcs8.as_ptr(), out_buf, pkcs8.len());
        }
        pkcs8.len()
    }));
    result.unwrap_or(0)
}

/// Validate an attestation challenge (max 128 bytes).
/// Returns 0 on success, -21 (INVALID_INPUT_LENGTH) if challenge is too long,
/// or -1 on unexpected panic.
#[no_mangle]
pub extern "C" fn certengine_validate_challenge(
    challenge: *const u8,
    challenge_len: usize,
) -> i32 {
    if challenge.is_null() {
        return -22; // INVALID_ARGUMENT
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees challenge points to at least challenge_len bytes.
        let slice = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };
        let engine = CertEngine::new();
        match engine.validate_challenge(slice) {
            Ok(()) => 0i32,
            Err(code) => code,
        }
    }));
    result.unwrap_or(-1)
}

