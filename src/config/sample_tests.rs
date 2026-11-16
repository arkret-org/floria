use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

fn collect_sample_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut files: Vec<_> = files
        .into_iter()
        .filter(|path| {
            path.extension().and_then(OsStr::to_str) == Some(extension)
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.contains(".sample."))
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no {extension} samples found under {}",
        root.display()
    );
    files
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let read_dir =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
    for entry in read_dir {
        let entry = entry.expect("read sample directory entry");
        let file_type = entry.file_type().expect("read sample file type");
        let path = entry.path();
        if file_type.is_dir() {
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
            if matches!(
                name,
                "target" | "artifacts" | ".git" | ".claude" | "node_modules"
            ) {
                continue;
            }
            walk(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

#[test]
fn sample_formats_load_to_the_same_valid_configuration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let kdl_paths = collect_sample_files(root, "kdl");
    let yaml_paths = collect_sample_files(root, "yaml");
    let kdl_stems: std::collections::BTreeSet<_> = kdl_paths
        .iter()
        .map(|path| path.with_extension(""))
        .collect();
    let yaml_stems: std::collections::BTreeSet<_> = yaml_paths
        .iter()
        .map(|path| path.with_extension(""))
        .collect();
    assert_eq!(kdl_stems, yaml_stems, "every sample must have both formats");
    for kdl_path in kdl_paths {
        let yaml_path = kdl_path.with_extension("yaml");
        let kdl_body = fs::read_to_string(&kdl_path).expect("read KDL sample");
        let yaml_body = fs::read_to_string(&yaml_path).expect("read YAML sample");
        let kdl_json = super::kdl::parse_kdl_to_json(&kdl_body)
            .unwrap_or_else(|error| panic!("{}: {error}", kdl_path.display()));
        let kdl: super::Config = serde_json::from_value(kdl_json)
            .unwrap_or_else(|error| panic!("{}: {error}", kdl_path.display()));
        let yaml: super::Config = serde_saphyr::from_str(&yaml_body)
            .unwrap_or_else(|error| panic!("{}: {error}", yaml_path.display()));
        kdl.validate()
            .unwrap_or_else(|error| panic!("{}: {error}", kdl_path.display()));
        yaml.validate()
            .unwrap_or_else(|error| panic!("{}: {error}", yaml_path.display()));
        assert_eq!(
            kdl,
            yaml,
            "{} and {} differ",
            kdl_path.display(),
            yaml_path.display()
        );
    }
}
