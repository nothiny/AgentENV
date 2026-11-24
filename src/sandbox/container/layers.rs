//! Sealed root filesystem layers shared between container sandboxes.
//!
//! Sealing a container's rootfs turns its writable upper into a read-only
//! layer and restacks the live device on top of it, so the sandbox keeps
//! running on that layer. Forked children stack their own uppers on it too,
//! and so do their children. Each sealed layer directory therefore lives
//! outside any one sandbox's work directory, counted by every sandbox whose
//! rootfs stacks on it, and is removed with its last reference.
//!
//! Counts are in memory: container sandboxes do not survive a server
//! restart, and startup reconciliation removes every layer directory.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use tracing::{debug, warn};

static REFERENCES: LazyLock<Mutex<HashMap<PathBuf, usize>>> = LazyLock::new(Default::default);

/// The sealed layer directories one sandbox's rootfs stacks on.
#[derive(Debug, Default)]
pub(super) struct LayerRefs(Vec<PathBuf>);

impl LayerRefs {
    /// Takes a reference to `dir` for this sandbox.
    pub(super) fn add(&mut self, dir: PathBuf) {
        *REFERENCES.lock().unwrap().entry(dir.clone()).or_default() += 1;
        self.0.push(dir);
    }

    /// References for a sandbox stacked on everything this one stacks on.
    pub(super) fn inherit(&self) -> Self {
        let mut child = Self::default();
        for dir in &self.0 {
            child.add(dir.clone());
        }
        child
    }

    /// Drops this sandbox's references and removes the directories nobody
    /// references any more. Call once the sandbox's devices are gone.
    pub(super) fn release(&mut self) {
        let unreferenced: Vec<PathBuf> = {
            let mut references = REFERENCES.lock().unwrap();
            self.0
                .drain(..)
                .filter(|dir| match references.get_mut(dir) {
                    Some(count) if *count > 1 => {
                        *count -= 1;
                        false
                    }
                    _ => {
                        references.remove(dir);
                        true
                    }
                })
                .collect()
        };
        for dir in unreferenced {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => debug!(layer = %dir.display(), "removed sealed rootfs layer"),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!(layer = %dir.display(), error = %err, "failed to remove sealed rootfs layer")
                }
            }
        }
    }

    #[cfg(test)]
    fn count(dir: &std::path::Path) -> usize {
        REFERENCES.lock().unwrap().get(dir).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layer_outlives_its_creator_while_children_use_it() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("layer");
        std::fs::create_dir_all(&dir).unwrap();

        let mut parent = LayerRefs::default();
        parent.add(dir.clone());
        let mut child = parent.inherit();
        let mut grandchild = child.inherit();
        assert_eq!(LayerRefs::count(&dir), 3);

        parent.release();
        child.release();
        assert!(dir.exists(), "the grandchild still stacks on the layer");
        grandchild.release();
        assert!(!dir.exists());
        assert_eq!(LayerRefs::count(&dir), 0);
    }
}
