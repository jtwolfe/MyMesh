use mymesh_core::{Error, Result};
use std::path::{Component, Path, PathBuf};

/// Restricts remote file ops to a root directory (no path escape).
#[derive(Clone, Debug)]
pub struct PathSandbox {
    root: PathBuf,
}

impl PathSandbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root_path = root.into();
        let root = root_path.canonicalize().unwrap_or(root_path);
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, remote: &str) -> Result<PathBuf> {
        let raw = Path::new(remote);
        let mut out = self.root.clone();
        for c in raw.components() {
            match c {
                Component::Normal(s) => out.push(s),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !out.pop() || !out.starts_with(&self.root) {
                        return Err(Error::PermissionDenied("path escapes sandbox".into()));
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    // Treat absolute as relative to sandbox root.
                }
            }
        }
        if !out.starts_with(&self.root) {
            return Err(Error::PermissionDenied("path escapes sandbox".into()));
        }
        Ok(out)
    }
}
