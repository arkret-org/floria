//! Lint-style scan over the committed `*.sample.{yaml,kdl}` configs.
//!
//! Sample configs ship as documentation. Real credentials embedded in
//! these files would be silently leaked through every clone of the
//! repository — so this test enforces that secret-bearing fields use
//! visibly-placeholder values (or are commented out entirely).
//!
//! The list of suspicious keys mirrors the credential fields documented
//! in `bridge/describe`'s `provider_capabilities`.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

const SECRET_KEYS: &[&str] = &[
    "app_key",
    "app_secret",
    "master_secret",
    "vapid_private_key",
    "service_account_file",
    "keyfile",
    "certfile",
    "bearer_tokens",
    "bearer_token_hashes",
    "signature_public_key_hex",
    "key_id",
    "team_id",
    "redis_url",
    "proxy",
];

/// Markers we consider obvious placeholders. If the value contains any
/// of these case-insensitive substrings we treat it as safe.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "your-",
    "replace-",
    "<replace",
    "<example",
    "example",
    "todo",
    "127.0.0.1",
    "localhost",
    "./",
    "AuthKey_",
    "test-",
    "redis://",
    "http://",
    "https://",
    "intent:",
    "0.0.0.0",
];

/// Allowed "values that look like real config but are actually
/// well-known constants" — IDs from sample placeholders.
const SAFE_NUMERIC_VALUES: &[&str] = &[
    "1234567890123456789",
    "100000001",
];

#[test]
fn sample_configs_do_not_contain_real_secrets() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut findings: Vec<String> = Vec::new();

    for entry in walk(manifest_dir) {
        let extension = entry
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let file_name = entry
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if !file_name.contains(".sample.") {
            continue;
        }
        if !matches!(extension, "yaml" | "yml" | "kdl") {
            continue;
        }
        let body = match fs::read_to_string(&entry) {
            Ok(body) => body,
            Err(error) => {
                findings.push(format!(
                    "could not read sample file {}: {error}",
                    entry.display()
                ));
                continue;
            }
        };
        for (line_no, line) in body.lines().enumerate() {
            if let Some(error) = scan_line(line) {
                findings.push(format!(
                    "{}:{}: {error} -- {line}",
                    entry.display(),
                    line_no + 1,
                    line = line.trim()
                ));
            }
        }
    }

    if !findings.is_empty() {
        panic!(
            "sample configs appear to contain real credentials:\n{}",
            findings.join("\n")
        );
    }
}

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    collect(root, &mut out);
    out
}

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        let path = entry.path();
        if file_type.is_dir() {
            // Skip target/, .git/, and worktrees so we don't double-scan.
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
            if matches!(name, "target" | ".git" | ".claude" | "node_modules") {
                continue;
            }
            collect(&path, out);
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}

fn scan_line(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    // Strip leading comment markers — commented lines are fine even if
    // they look like secrets.
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    let (key, value) = match trimmed.find(':') {
        Some(idx) => (trimmed[..idx].trim(), trimmed[idx + 1..].trim()),
        None => match trimmed.split_once(char::is_whitespace) {
            Some((key, value)) => (key.trim(), value.trim()),
            None => return None,
        },
    };

    // Strip quotes / inline comments / list marker.
    let value = value
        .trim_start_matches(['-', ' '])
        .split_once('#')
        .map(|(left, _)| left)
        .unwrap_or(value)
        .trim()
        .trim_matches(|c| c == '"' || c == '\'');
    if value.is_empty() {
        return None;
    }

    let lowered_key = key.to_ascii_lowercase();
    if !SECRET_KEYS
        .iter()
        .any(|candidate| lowered_key.eq_ignore_ascii_case(candidate))
    {
        return None;
    }

    if value_is_placeholder(value) {
        return None;
    }

    Some("non-placeholder credential value in sample config")
}

fn value_is_placeholder(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lowered.contains(&marker.to_ascii_lowercase()))
    {
        return true;
    }
    if SAFE_NUMERIC_VALUES.contains(&value) {
        return true;
    }
    // Pure placeholder objects / empty maps.
    if value == "{}" || value == "[]" || value == "null" {
        return true;
    }
    false
}
