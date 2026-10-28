//! Offline stand-in for serde_json::from_str (catalog API sink rust.sink.api.from_str).
pub fn from_str(s: &str) -> usize {
    let _ = s;
    0
}
