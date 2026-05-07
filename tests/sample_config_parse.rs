//! Verifies that the committed `*.sample.{yaml,kdl}` configs parse with
//! the production parser. Catches drift between the documented examples
//! and the active KDL/YAML grammar (e.g. KDL 2.0 boolean syntax).

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

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

fn collect_sample_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out);
    out.into_iter()
        .filter(|path| {
            path.extension().and_then(OsStr::to_str) == Some(extension)
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.contains(".sample."))
        })
        .collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
            if matches!(name, "target" | ".git" | ".claude" | "node_modules") {
                continue;
            }
            walk(&path, out);
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}
