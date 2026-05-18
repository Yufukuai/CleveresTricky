//! Play Integrity Protection Logic
//! Memory-safe implementation of integrity service detection and rate limiting.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const INTEGRITY_SERVICE_DESCRIPTOR: &str = "com.google.android.play.core.integrity";
const GMS_INTEGRITY_DESCRIPTOR: &str = "com.google.android.gms.playintegrity";

const REMEDIATION_GET_INTEGRITY: &str = "GET_INTEGRITY";
const REMEDIATION_GET_STRONG_INTEGRITY: &str = "GET_STRONG_INTEGRITY";
const REMEDIATION_GET_LICENSED: &str = "GET_LICENSED";
const REMEDIATION_CLOSE_ACCESS_RISK: &str = "CLOSE_UNKNOWN_ACCESS_RISK";

const INTEGRITY_WARMUP_CODE: u32 = 1;
const INTEGRITY_REQUEST_CODE: u32 = 2;
const INTEGRITY_STANDARD_CODE: u32 = 3;

const MAX_REQUESTS_PER_MINUTE: usize = 5;

static WINDOW_START_MS: AtomicI64 = AtomicI64::new(0);
static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn is_integrity_service_descriptor(descriptor: &str) -> bool {
    if descriptor.is_empty() {
        return false;
    }
    if descriptor.contains(INTEGRITY_SERVICE_DESCRIPTOR) {
        return true;
    }
    if descriptor.contains(GMS_INTEGRITY_DESCRIPTOR) {
        return true;
    }
    if descriptor.contains("playintegrity") {
        return true;
    }
    if descriptor.contains("PlayIntegrity") {
        return true;
    }
    if descriptor.contains("firebase.appcheck") {
        return true;
    }
    false
}

pub fn is_recall_related_transaction(code: u32, descriptor: &str) -> bool {
    if !is_integrity_service_descriptor(descriptor) {
        return false;
    }
    if code == INTEGRITY_WARMUP_CODE
        || code == INTEGRITY_REQUEST_CODE
        || code == INTEGRITY_STANDARD_CODE
    {
        return true;
    }
    // High-range transaction codes (1 to 10)
    if (1..=10).contains(&code) {
        return true;
    }
    false
}

pub fn is_integrity_verdict_transaction(code: u32, descriptor: &str) -> bool {
    is_integrity_service_descriptor(descriptor) && code >= 1
}

pub fn is_remediation_dialog_intent(action: &str) -> bool {
    if action.is_empty() {
        return false;
    }
    if action.contains(REMEDIATION_GET_INTEGRITY) {
        return true;
    }
    if action.contains(REMEDIATION_GET_STRONG_INTEGRITY) {
        return true;
    }
    if action.contains(REMEDIATION_GET_LICENSED) {
        return true;
    }
    if action.contains(REMEDIATION_CLOSE_ACCESS_RISK) {
        return true;
    }
    false
}

pub fn record_token_request() {
    let now_ms = current_time_ms();
    let window_start = WINDOW_START_MS.load(Ordering::Relaxed);

    if now_ms - window_start > 60000 {
        WINDOW_START_MS.store(now_ms, Ordering::Relaxed);
        REQUEST_COUNT.store(1, Ordering::Relaxed);
    } else {
        REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn is_request_rate_normal() -> bool {
    let count = REQUEST_COUNT.load(Ordering::Relaxed);
    count <= MAX_REQUESTS_PER_MINUTE
}
