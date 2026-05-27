//! KDL ↔ YAML parity coverage.
//!
//! For every `*.sample.kdl` we expect a sibling `*.sample.yaml`. Both
//! must parse, normalize to the same `Config`, and serialize to the same
//! canonical JSON form. Drift between the two formats is a docs bug —
//! operators copy/paste between them and expect identical semantics.
//!
//! Also gates `floria.config.schema.json`: the committed file's `$id`
//! must encode `Config::SCHEMA_VERSION` so the schema artifact never
//! gets out of sync with the runtime parser.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use floria::config::Config;
use serde_json::Value;

#[test]
fn every_sample_kdl_has_matching_yaml_pair() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let kdl_files = collect_sample_files(manifest_dir, "kdl");
    assert!(
        !kdl_files.is_empty(),
        "expected at least one *.sample.kdl in the repo"
    );

    let mut missing = Vec::new();
    for kdl in &kdl_files {
        let yaml = path_with_swapped_extension(kdl, "kdl", "yaml");
        if !yaml.exists() {
            missing.push(format!("{} (no sibling .yaml)", kdl.display()));
        }
    }
    if !missing.is_empty() {
        panic!(
            "sample KDL files missing YAML siblings:\n{}",
            missing.join("\n")
        );
    }
}

#[test]
fn sample_kdl_and_yaml_parse_to_equivalent_config() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut mismatches = Vec::new();

    for kdl_path in collect_sample_files(manifest_dir, "kdl") {
        let yaml_path = path_with_swapped_extension(&kdl_path, "kdl", "yaml");
        if !yaml_path.exists() {
            continue; // covered by the pair-presence test above
        }

        let kdl_body = fs::read_to_string(&kdl_path).expect("read sample kdl");
        let yaml_body = fs::read_to_string(&yaml_path).expect("read sample yaml");

        let kdl_json = match Config::parse_kdl_to_json(&kdl_body) {
            Ok(v) => v,
            Err(error) => {
                mismatches.push(format!("{}: KDL parse failed: {error}", kdl_path.display()));
                continue;
            }
        };
        let yaml_value: Value = match serde_saphyr::from_str(&yaml_body) {
            Ok(v) => v,
            Err(error) => {
                mismatches.push(format!(
                    "{}: YAML parse failed: {error}",
                    yaml_path.display()
                ));
                continue;
            }
        };

        // Normalize away projection-only differences between the two
        // formats that don't change Config semantics:
        //   - YAML's `key:` with no value → `null`; KDL emits `{}` for
        //     a node with no children. Both deserialize to the type's
        //     `Default` value, so we elide nulls and empty objects.
        //   - YAML lists vs KDL single-child scalar (`bind_addresses`).
        //     Wrap KDL scalars into 1-element arrays where YAML used a
        //     list, by promoting scalars when the sibling has a list.
        //   - KDL preserves large integers as strings; YAML promotes
        //     them to JSON numbers. Coerce integer-shaped strings into
        //     numbers when the sibling has a number.
        let mut kdl_norm = kdl_json.clone();
        let mut yaml_norm = yaml_value.clone();
        normalize_for_parity(&mut kdl_norm, &mut yaml_norm);

        // Smoke check: at least one side should typecheck — if both
        // fail, the samples are simply broken.
        let kdl_typed: std::result::Result<Config, _> = serde_json::from_value(kdl_norm.clone());
        let yaml_typed: std::result::Result<Config, _> = serde_json::from_value(yaml_norm.clone());
        if let (Err(ke), Err(ye)) = (&kdl_typed, &yaml_typed) {
            mismatches.push(format!(
                "{} / {}: both sides fail Config deserialization\n  KDL : {ke}\n  YAML: {ye}",
                kdl_path.display(),
                yaml_path.display(),
            ));
            continue;
        }

        let kdl_canon = canonicalize(&kdl_norm);
        let yaml_canon = canonicalize(&yaml_norm);

        if kdl_canon != yaml_canon {
            mismatches.push(format!(
                "{} ↔ {}: normalized config diverges\n  KDL : {}\n  YAML: {}",
                kdl_path.display(),
                yaml_path.display(),
                kdl_canon,
                yaml_canon,
            ));
        }
    }

    if !mismatches.is_empty() {
        panic!("KDL ↔ YAML parity violated:\n{}", mismatches.join("\n\n"));
    }
}

#[test]
fn committed_schema_id_encodes_current_schema_version() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema_path = manifest_dir.join("floria.config.schema.json");
    let body = fs::read_to_string(&schema_path).expect("read floria.config.schema.json");
    let schema: Value = serde_json::from_str(&body).expect("parse schema JSON");

    let id = schema
        .get("$id")
        .and_then(Value::as_str)
        .expect("schema must declare $id");
    let x_version = schema
        .get("x-floria-schema-version")
        .and_then(Value::as_str)
        .expect("schema must declare x-floria-schema-version");

    assert_eq!(
        x_version,
        Config::SCHEMA_VERSION,
        "x-floria-schema-version drifted from Config::SCHEMA_VERSION"
    );
    assert!(
        id.contains(Config::SCHEMA_VERSION),
        "$id ({id}) does not encode Config::SCHEMA_VERSION ({})",
        Config::SCHEMA_VERSION
    );

    // The runtime schema generator must also agree.
    let runtime = floria::config::config_json_schema();
    assert_eq!(
        runtime.get("$id"),
        schema.get("$id"),
        "runtime config_json_schema() $id drifted from committed schema",
    );
    assert_eq!(
        runtime.get("x-floria-schema-version"),
        schema.get("x-floria-schema-version"),
        "runtime config_json_schema() version drifted from committed schema",
    );
}

// ── helpers ─────────────────────────────────────────────────────────

/// Reconcile projection-only differences between the KDL and YAML
/// renderings of the same logical config. The function mutates both
/// sides so the parity assertion compares semantic content only.
fn normalize_for_parity(kdl: &mut Value, yaml: &mut Value) {
    // 1. Drop nulls and empty objects everywhere — both map to Default.
    strip_empty(kdl);
    strip_empty(yaml);
    // 2. Co-shape scalars/arrays + numeric-vs-string fields recursively.
    coshape(kdl, yaml);
}

fn strip_empty(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<_> = map.keys().cloned().collect();
            for k in keys {
                if let Some(child) = map.get_mut(&k) {
                    strip_empty(child);
                }
                let drop = match map.get(&k) {
                    Some(Value::Null) => true,
                    Some(Value::Object(m)) => m.is_empty(),
                    _ => false,
                };
                if drop {
                    map.remove(&k);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                strip_empty(item);
            }
        }
        _ => {}
    }
}

fn coshape(a: &mut Value, b: &mut Value) {
    // If one side is a 1-element array and the other is a matching
    // scalar, lift the scalar into an array.
    match (a, b) {
        (Value::Object(am), Value::Object(bm)) => {
            let keys: std::collections::BTreeSet<String> =
                am.keys().chain(bm.keys()).cloned().collect();
            for k in keys {
                if let (Some(av), Some(bv)) = (am.get_mut(&k), bm.get_mut(&k)) {
                    coshape(av, bv);
                }
            }
        }
        (Value::Array(av), Value::Array(bv)) => {
            for (x, y) in av.iter_mut().zip(bv.iter_mut()) {
                coshape(x, y);
            }
        }
        (a_val, b_val) => {
            // scalar ↔ 1-element-array: promote the scalar
            if let Value::Array(arr) = b_val
                && arr.len() == 1
                && !matches!(a_val, Value::Array(_) | Value::Object(_))
            {
                *a_val = Value::Array(vec![a_val.take()]);
                return;
            }
            if let Value::Array(arr) = a_val
                && arr.len() == 1
                && !matches!(b_val, Value::Array(_) | Value::Object(_))
            {
                *b_val = Value::Array(vec![b_val.take()]);
                return;
            }
            // string-integer ↔ number: coerce the string to a number
            if let (Value::String(s), Value::Number(_)) = (&*a_val, &*b_val) {
                if let Ok(n) = s.parse::<i64>() {
                    *a_val = Value::Number(n.into());
                } else if let Ok(n) = s.parse::<u64>() {
                    *a_val = Value::Number(n.into());
                }
            } else if let (Value::Number(_), Value::String(s)) = (&*a_val, &*b_val) {
                if let Ok(n) = s.parse::<i64>() {
                    *b_val = Value::Number(n.into());
                } else if let Ok(n) = s.parse::<u64>() {
                    *b_val = Value::Number(n.into());
                }
            }
        }
    }
}

/// Recursively sort object keys and JSON-stringify so the comparison is
/// order-independent. `serde_json::Value` already implements `PartialEq`
/// for maps in an order-independent way, but the canonical string is
/// useful for the assertion error message.
fn canonicalize(value: &Value) -> String {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf);
    String::from_utf8(buf).expect("canonical JSON is utf-8")
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    use std::io::Write as _;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write!(out, "{}", serde_json::to_string(k).unwrap()).unwrap();
                out.push(b':');
                write_canonical(v, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(v, out);
            }
            out.push(b']');
        }
        other => {
            write!(out, "{}", serde_json::to_string(other).unwrap()).unwrap();
        }
    }
}

fn path_with_swapped_extension(path: &Path, from: &str, to: &str) -> PathBuf {
    if path.extension().and_then(OsStr::to_str) == Some(from) {
        path.with_extension(to)
    } else {
        path.to_path_buf()
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
