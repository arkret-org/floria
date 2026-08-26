//! Verifies that the committed `*.sample.{yaml,kdl}` configs parse with
//! the production parser. Catches drift between the documented examples
//! and the active KDL/YAML grammar (e.g. KDL 2.0 boolean syntax).

use std::fs;
use std::path::Path;

mod common;
use common::collect_sample_files;

#[test]
fn every_sample_kdl_file_parses() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut failures = Vec::new();
    for path in collect_sample_files(manifest_dir, "kdl") {
        let body = fs::read_to_string(&path).expect("read sample kdl");
        if let Err(error) = body.parse::<kdl::KdlDocument>() {
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    if !failures.is_empty() {
        panic!(
            "sample KDL files failed to parse with the active kdl crate:\n{}",
            failures.join("\n")
        );
    }
}

#[test]
fn every_sample_yaml_file_parses() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut failures = Vec::new();
    for path in collect_sample_files(manifest_dir, "yaml") {
        let body = fs::read_to_string(&path).expect("read sample yaml");
        if let Err(error) = serde_saphyr::from_str::<serde_json::Value>(&body) {
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    if !failures.is_empty() {
        panic!(
            "sample YAML files failed to parse:\n{}",
            failures.join("\n")
        );
    }
}
