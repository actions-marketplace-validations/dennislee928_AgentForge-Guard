#![no_main]
//! Shell-string tokenizing never panics, and re-quoting its output
//! reproduces the same commands.
use afg_core::shell::split_commands;
use libfuzzer_sys::fuzz_target;

fn quote(a: &str) -> String {
    format!("'{}'", a.replace('\'', r"'\''"))
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(cmds) = split_commands(&s) {
        let again: String = cmds.iter().map(|c| c.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join("; ");
        assert_eq!(split_commands(&again).unwrap(), cmds);
    }
});
