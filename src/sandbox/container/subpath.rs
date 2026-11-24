//! Exposing a drive's `subPath` without letting the drive's contents choose
//! what gets bound.
//!
//! The drive is guest-writable, so any component of the sub-path may be a
//! symbolic link planted by an earlier sandbox. The privileged runtime
//! resolves a bind source in the server's mount namespace, so a plain
//! `drive_root.join(sub_path)` could bind host files into the sandbox. The
//! sub-path is instead opened one component at a time with `openat2`
//! beneath the drive root, refusing links and mount crossings, and the
//! resulting object is pinned by bind-mounting its descriptor onto a staging
//! path the runtime then binds from.

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use nix::errno::Errno;
use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{fstat, mkdirat, Mode, SFlag};

fn resolve_flags() -> ResolveFlag {
    ResolveFlag::RESOLVE_BENEATH
        | ResolveFlag::RESOLVE_NO_SYMLINKS
        | ResolveFlag::RESOLVE_NO_MAGICLINKS
        | ResolveFlag::RESOLVE_NO_XDEV
}

/// Opens one component. Without `O_NOFOLLOW`, `RESOLVE_NO_SYMLINKS` fails a
/// trailing link with ELOOP; with it, `O_PATH` would return the link itself.
fn open_component(dir: &OwnedFd, name: &Path) -> nix::Result<OwnedFd> {
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
        .resolve(resolve_flags());
    let fd = openat2(dir, name, how)?;
    // Defense in depth: never hand out a descriptor of a link.
    match file_type(&fd) {
        Ok(SFlag::S_IFLNK) => Err(Errno::ELOOP),
        _ => Ok(fd),
    }
}

fn file_type(fd: &OwnedFd) -> nix::Result<SFlag> {
    Ok(SFlag::from_bits_truncate(fstat(fd)?.st_mode) & SFlag::S_IFMT)
}

fn is_dir(fd: &OwnedFd) -> Result<bool> {
    Ok(file_type(fd).context("stat sub-path component")? == SFlag::S_IFDIR)
}

/// Opens `sub_path` beneath `root` as an `O_PATH` descriptor. Missing
/// components are created as directories, as the guest's `mkdir -p` would
/// on Firecracker. Any link, `..`, absolute component or mount crossing is
/// refused.
pub(super) fn open_beneath(root: &Path, sub_path: &Path) -> Result<OwnedFd> {
    let mut current: OwnedFd = File::open(root)
        .with_context(|| format!("open drive root {}", root.display()))?
        .into();
    let components: Vec<_> = sub_path.components().collect();
    if components.is_empty() {
        bail!("subPath is empty");
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            bail!(
                "subPath {} must be relative without '..'",
                sub_path.display()
            );
        };
        let name = Path::new(name);
        let next = match open_component(&current, name) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                match mkdirat(&current, name, Mode::from_bits_truncate(0o755)) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(err) => bail!("create subPath component {}: {err}", name.display()),
                }
                open_component(&current, name)
                    .with_context(|| format!("open created subPath component {}", name.display()))?
            }
            Err(Errno::ELOOP) => bail!(
                "subPath {} crosses a symbolic link at {}",
                sub_path.display(),
                name.display()
            ),
            Err(Errno::EXDEV) => bail!(
                "subPath {} crosses a mount at {}",
                sub_path.display(),
                name.display()
            ),
            Err(err) => bail!("open subPath component {}: {err}", name.display()),
        };
        if index + 1 < components.len() && !is_dir(&next)? {
            bail!("subPath component {} is not a directory", name.display());
        }
        current = next;
    }
    Ok(current)
}

/// Binds the object `fd` refers to onto `target`, created to match it.
/// The bind goes through the descriptor, so nothing is looked up by path.
pub(super) fn pin(fd: &OwnedFd, target: &Path) -> Result<()> {
    if is_dir(fd)? {
        std::fs::create_dir_all(target)
            .with_context(|| format!("create bind target {}", target.display()))?;
    } else {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        File::create(target).with_context(|| format!("create bind target {}", target.display()))?;
    }
    let source = format!("/proc/self/fd/{}", fd.as_raw_fd());
    mount(
        Some(source.as_str()),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("bind subPath onto {}", target.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("root/data/inner")).unwrap();
        std::fs::write(temp.path().join("root/data/file"), b"x").unwrap();
        std::fs::create_dir_all(temp.path().join("outside")).unwrap();
        temp
    }

    #[test]
    fn opens_existing_and_creates_missing_components() {
        let temp = fixture();
        let root = temp.path().join("root");
        let fd = open_beneath(&root, Path::new("data/inner")).unwrap();
        assert!(is_dir(&fd).unwrap());
        assert!(!is_dir(&open_beneath(&root, Path::new("data/file")).unwrap()).unwrap());
        open_beneath(&root, Path::new("new/nested")).unwrap();
        assert!(root.join("new/nested").is_dir());
    }

    #[test]
    fn refuses_links_in_any_component() {
        let temp = fixture();
        let root = temp.path().join("root");
        // A final component that links out of the drive.
        symlink(temp.path().join("outside"), root.join("escape")).unwrap();
        // An intermediate component that does.
        symlink(temp.path().join("outside"), root.join("data/hop")).unwrap();
        // A relative link that stays inside is refused too: links are never
        // followed.
        symlink("inner", root.join("data/rel")).unwrap();
        for sub_path in ["escape", "escape/x", "data/hop", "data/hop/x", "data/rel"] {
            let err = open_beneath(&root, Path::new(sub_path)).unwrap_err();
            assert!(
                err.to_string().contains("symbolic link"),
                "{sub_path}: {err:#}"
            );
        }
        assert!(!temp.path().join("outside/x").exists());
    }

    #[test]
    fn refuses_parent_and_absolute_components() {
        let temp = fixture();
        let root = temp.path().join("root");
        for sub_path in ["../outside", "data/../../outside", "/etc"] {
            assert!(
                open_beneath(&root, Path::new(sub_path)).is_err(),
                "{sub_path}"
            );
        }
    }

    #[test]
    fn refuses_a_file_in_the_middle() {
        let temp = fixture();
        let err = open_beneath(&temp.path().join("root"), Path::new("data/file/x")).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err:#}");
    }
}
