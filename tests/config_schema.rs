//! `--check` gate for the generated config schema artifact.
//!
//! `floria::config::config_json_schema` is the single source of truth;
//! `floria.config.schema.json` at the repository root is generated from
//! it. These tests fail the build if the artifact drifts, or if the
//! schema version is written in more than one place.

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

/// The schema version appears twice in the document (`$id` and
/// `x-floria-schema-version`). Both derive from `Config::SCHEMA_VERSION`,
/// so a bump can never update one and leave the other behind.
#[test]
fn schema_version_is_single_sourced() {
    let schema = generated();
    let version = schema
        .get("x-floria-schema-version")
        .and_then(Value::as_str)
        .expect("schema must carry x-floria-schema-version");
    let id = schema
        .get("$id")
        .and_then(Value::as_str)
        .expect("schema must carry $id");

    assert_eq!(
        id,
        format!("https://arkret.dev/schema/floria/{version}/floria.config.schema.json"),
        "$id must embed x-floria-schema-version"
    );
}
