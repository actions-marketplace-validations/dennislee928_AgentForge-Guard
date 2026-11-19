#![no_main]
//! Arbitrary YAML never panics the parser or the validator.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(p) = afg_core::Policy::from_yaml(s)
    {
        let _ = afg_core::validate::validate(&p);
    }
});
