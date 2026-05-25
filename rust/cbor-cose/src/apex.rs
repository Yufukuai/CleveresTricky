use rustc_hash::FxHashMap;
use std::sync::RwLock;

static APEX_CACHE: RwLock<Option<FxHashMap<Box<str>, Box<str>>>> = RwLock::new(None);

pub fn get_spoofed_apex_info<R, F: FnOnce(&str) -> R>(name: &str, f: F) -> Option<R> {
    if let Ok(cache) = APEX_CACHE.read() {
        if let Some(c) = cache.as_ref() {
            if let Some(ver) = c.get(name) {
                return Some(f(ver.as_ref()));
            }
        }
    }

    // Default spoofed APEX versions for critical modules
    match name {
        "com.android.tzdata" => Some(f("350090000")),
        "com.android.conscrypt" => Some(f("350090000")),
        "com.google.android.extservices" => Some(f("350090000")),
        "com.android.resolv" => Some(f("350090000")),
        _ => None,
    }
}
