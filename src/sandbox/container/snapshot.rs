//! Memory snapshots of container sandboxes.
//!
//! A snapshot is captured like a full fork, in one frozen window: the
//! processes are dumped with CRIU, the writable volumes and the rootfs sealed.
//! The snapshot pipeline then stores it like a Firecracker one:
//! - `vm_state` is a tar of the CRIU images;
//! - the rootfs is the sealed OverlayBD stack;
//! - read-only attached drives are attached drives;
//! - volumes are published by the volume catalog;
//! - there is no memory image, since the CRIU images hold the memory;
//! - [`ContainerSnapshotSection`] records what a restore must rebuild.
//!
//! A sandbox launched from the snapshot is a new container (own ID, token,
//! rootfs upper, volumes, network slot, cgroup) that unpacks the images and
//! `runc restore`s them. CRIU restores exactly the mounts it dumped, so the
//! launch's drives must bind at the same paths, read-only where they were.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::snapshot::{ContainerSnapshotMount, ContainerSnapshotSection};
use crate::types::ExtraDrive;

/// The file in a tools image that names its release.
pub(super) const TOOLS_VERSION_FILE: &str = "tools/agentenv/tools-drive-version";

/// Tars the CRIU images in `dir` into `archive`.
pub(super) async fn pack(dir: PathBuf, archive: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::create(&archive)
            .with_context(|| format!("create {}", archive.display()))?;
        let mut builder = tar::Builder::new(std::io::BufWriter::new(file));
        builder.follow_symlinks(false);
        builder
            .append_dir_all(".", &dir)
            .with_context(|| format!("archive {}", dir.display()))?;
        builder
            .into_inner()
            .context("finish CRIU image archive")?
            .into_inner()
            .map_err(|err| err.into_error())
            .context("flush CRIU image archive")?
            .sync_all()
            .context("sync CRIU image archive")
    })
    .await
    .context("join CRIU image archiving")?
}

/// Unpacks the CRIU images in `archive` into `dir`.
pub(super) async fn unpack(archive: PathBuf, dir: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let file =
            std::fs::File::open(&archive).with_context(|| format!("open {}", archive.display()))?;
        let mut tar = tar::Archive::new(std::io::BufReader::new(file));
        tar.set_preserve_permissions(true);
        tar.unpack(&dir)
            .with_context(|| format!("unpack {} into {}", archive.display(), dir.display()))
    })
    .await
    .context("join CRIU image unpacking")?
}

/// The drives a sandbox launched from a container snapshot attaches, in the
/// dumped container's order:
/// - each attached drive from the snapshot;
/// - each volume from `launch`, which restored the snapshot's volumes.
///
/// A drive the dump had no mount for, or one at a dumped path that is
/// missing or differs in being read-only, is refused.
pub(super) fn arrange_drives(
    section: &ContainerSnapshotSection,
    attached: &[ExtraDrive],
    launch: &[ExtraDrive],
) -> Result<Vec<ExtraDrive>> {
    let mut used = vec![false; launch.len()];
    let mut drives = Vec::with_capacity(section.mounts.len());
    for mount in &section.mounts {
        let drive = if mount.volume {
            let index = launch
                .iter()
                .position(|drive| drive.mount_path() == mount.path)
                .with_context(|| {
                    format!(
                        "the snapshot's container had a volume at {}, which this launch does \
                         not mount",
                        mount.path.display()
                    )
                })?;
            used[index] = true;
            launch[index].clone()
        } else {
            attached
                .iter()
                .find(|drive| drive.mount_path() == mount.path)
                .cloned()
                .with_context(|| {
                    format!(
                        "the snapshot has no attached drive for {}",
                        mount.path.display()
                    )
                })?
        };
        if drive.read_only() != mount.read_only {
            bail!(
                "{} was {} in the snapshot's container, and the launch mounts it {}",
                mount.path.display(),
                access(mount.read_only),
                access(drive.read_only())
            );
        }
        drives.push(drive);
    }
    if let Some(extra) = launch
        .iter()
        .zip(&used)
        .find_map(|(drive, used)| (!used).then_some(drive))
    {
        bail!(
            "a sandbox launched from a container snapshot cannot add a drive: the snapshot's \
             container had nothing mounted at {}",
            extra.mount_path().display()
        );
    }
    Ok(drives)
}

fn access(read_only: bool) -> &'static str {
    if read_only {
        "read-only"
    } else {
        "writable"
    }
}

/// The mounts a snapshot of a container with `drives` records.
pub(super) fn mounts_of(drives: &[ExtraDrive]) -> Vec<ContainerSnapshotMount> {
    drives
        .iter()
        .map(|drive| ContainerSnapshotMount {
            path: drive.mount_path().to_path_buf(),
            read_only: drive.read_only(),
            volume: drive.is_volume(),
        })
        .collect()
}

/// The release of the tools image mounted under `work_dir`.
pub(super) fn tools_version(work_dir: &Path) -> Result<String> {
    let path = work_dir.join(TOOLS_VERSION_FILE);
    let version = std::fs::read_to_string(&path)
        .with_context(|| format!("read the tools image release from {}", path.display()))?;
    let version = version.trim();
    if version.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SandboxResources;

    fn drive(id: &str, path: &str, read_only: bool, volume: bool) -> ExtraDrive {
        let drive = ExtraDrive::try_new_overlaybd_with_mount_path(
            id.to_owned(),
            PathBuf::from(format!("/images/{id}.json")),
            read_only,
            PathBuf::from(path),
            None::<PathBuf>,
        )
        .unwrap()
        .try_with_virtual_size(64 << 20)
        .unwrap();
        // A volume is a drive with an output directory to seal into.
        if volume {
            drive.with_volume_snapshot_output_dir(Some(PathBuf::from(format!("/vol/{id}"))))
        } else {
            drive
        }
    }

    fn section(mounts: Vec<ContainerSnapshotMount>) -> ContainerSnapshotSection {
        ContainerSnapshotSection {
            runtime: "runc".into(),
            tools_version: "0.1.2".into(),
            envd_port: 49983,
            auth_mount: true,
            resources: SandboxResources::default(),
            mounts,
        }
    }

    #[test]
    fn a_launch_rebuilds_the_dumped_mounts_in_order() {
        let dumped = [
            drive("data", "/data", false, true),
            drive("models", "/models", true, false),
        ];
        let section = section(mounts_of(&dumped));
        let attached = [drive("models", "/models", true, false)];
        let launch = [drive("vol_new", "/data", false, true)];
        let drives = arrange_drives(&section, &attached, &launch).unwrap();
        let ids: Vec<_> = drives.iter().map(ExtraDrive::drive_id).collect();
        assert_eq!(ids, ["vol_new", "models"]);
    }

    #[test]
    fn a_launch_cannot_add_drop_or_change_a_mount() {
        let section = section(mounts_of(&[drive("data", "/data", false, true)]));
        let extra = [
            drive("vol_new", "/data", false, true),
            drive("more", "/more", false, true),
        ];
        let err = arrange_drives(&section, &[], &extra).unwrap_err();
        assert!(format!("{err:#}").contains("cannot add a drive"), "{err:#}");

        let err = arrange_drives(&section, &[], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("does not mount"), "{err:#}");

        let read_only = [drive("vol_new", "/data", true, true)];
        let err = arrange_drives(&section, &[], &read_only).unwrap_err();
        assert!(format!("{err:#}").contains("writable"), "{err:#}");
    }

    #[tokio::test]
    async fn the_images_survive_packing() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let images = temp.path().join("criu");
        std::fs::create_dir_all(&images)?;
        std::fs::write(images.join("inventory.img"), b"inventory")?;
        std::fs::write(images.join("pages-1.img"), vec![7u8; 1 << 16])?;
        let archive = temp.path().join("criu.tar");
        pack(images.clone(), archive.clone()).await?;
        let restored = temp.path().join("restored");
        unpack(archive, restored.clone()).await?;
        assert_eq!(std::fs::read(restored.join("inventory.img"))?, b"inventory");
        assert_eq!(
            std::fs::read(restored.join("pages-1.img"))?,
            vec![7u8; 1 << 16]
        );
        Ok(())
    }
}
