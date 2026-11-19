//! JSON Schema for `agentforge.yaml`, used for IDE autocomplete and by
//! external validators.

/// The policy JSON Schema, pretty-printed with a trailing newline.
pub fn policy_schema_json() -> String {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<crate::Policy>();
    let mut out = serde_json::to_string_pretty(&schema).expect("schema serializes");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The committed `agentforge.schema.json` must match the generated one.
    /// Run with `AFG_BLESS=1` to regenerate it.
    #[test]
    fn committed_schema_is_up_to_date() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../agentforge.schema.json");
        let generated = policy_schema_json();
        if std::env::var_os("AFG_BLESS").is_some() {
            std::fs::write(&path, &generated).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == generated,
            "agentforge.schema.json is stale; run `AFG_BLESS=1 cargo test -p afg-core schema`"
        );
    }

    #[test]
    fn schema_describes_strict_policy() {
        let v: serde_json::Value = serde_json::from_str(&policy_schema_json()).unwrap();
        assert_eq!(v["title"], "Policy");
        assert_eq!(v["additionalProperties"], false);
        let req = v["required"].as_array().unwrap();
        assert!(req.iter().any(|r| r == "apiVersion"));
    }
}
