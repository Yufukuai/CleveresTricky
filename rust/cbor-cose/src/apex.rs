use rustc_hash::FxHashMap;
use std::sync::RwLock;

static APEX_CACHE: RwLock<Option<FxHashMap<Box<str>, Box<str>>>> = RwLock::new(None);

pub fn get_spoofed_apex_info(name: &str) -> Option<String> {
    if let Ok(cache) = APEX_CACHE.read() {
        if let Some(c) = cache.as_ref() {
            if let Some(ver) = c.get(name) {
                return Some(ver.to_string());
            }
        }
    }

    // Default spoofed APEX versions for critical modules
    match name {
        "com.android.tzdata" => Some("350090000".to_string()),
        "com.android.conscrypt" => Some("350090000".to_string()),
        "com.google.android.extservices" => Some("350090000".to_string()),
        "com.android.resolv" => Some("350090000".to_string()),
        _ => None,
    }
}
