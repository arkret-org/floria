use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn collect_sample_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, &mut files);
    files
        .into_iter()
        .filter(|path| {
            path.extension().and_then(OsStr::to_str) == Some(extension)
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.contains(".sample."))
        })
        .collect()
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
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
            walk(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}
