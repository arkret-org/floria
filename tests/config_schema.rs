//! `--check` gate for the generated config schema artifact.
//!
//! `floria::config::config_json_schema` is the single source of truth;
//! `floria.config.schema.json` at the repository root is generated from
//! it. The test fails the build if the artifact drifts.

use serde_json::Value;

fn generated() -> Value {
    floria::config::config_json_schema()
}

#[test]
fn committed_config_schema_matches_generator() {
    let generated = format!(
        "{}\n",
        serde_json::to_string_pretty(&generated()).expect("config schema must serialize")
    );
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/floria.config.schema.json"
    ))
    .expect("committed config schema must be readable");

    assert_eq!(
        committed, generated,
        "floria.config.schema.json drifted; run `cargo run --example emit_schema > floria.config.schema.json`"
    );
}
