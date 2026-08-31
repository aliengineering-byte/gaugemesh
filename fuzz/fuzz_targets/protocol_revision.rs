#![no_main]

use gaugemesh_core::protocol::McpRevision;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = McpRevision::parse(text);
    }
});
