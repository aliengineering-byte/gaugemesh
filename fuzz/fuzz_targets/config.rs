#![no_main]

use gaugemesh_core::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let parsed = serde_yaml::from_str::<Config>(text);
        if let Ok(config) = parsed {
            let _ = config.validate();
        }
    }
});
