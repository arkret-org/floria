//! Emit the canonical floria config JSON schema to stdout.
//!
//! Run with `cargo run --example emit_schema > floria.config.schema.json` to
//! refresh the artifact after the configuration contract changes.

fn main() {
    let schema = floria::config::config_json_schema();
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("schema must serialize")
    );
}
