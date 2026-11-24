//! OCI container backend.
//!
//! A container sandbox runs under an OCI runtime (runc, crun or runsc) on the
//! same OverlayBD rootfs device Firecracker would attach, with the tools drive
//! mounted read-only at `/agentenv` and envd as PID 1. Its network is a leased
//! slot whose `tap0` is replaced by a veth pair into the container's own
//! namespace (see [`netns`]).
//!
//! Requires the server to run as root: rootful OCI runtimes need the full
//! capability set, which the non-root systemd unit does not grant.
//!
//! Supported: cold start, exec, files, proxy, delete, egress rules, network
//! policy updates, managed volumes, attached drives, root filesystem capture
//! for publishing as an image, and filesystem-only forks. Pause and
//! memory snapshots are rejected before they reach this backend (see
//! `SandboxBackendKind::supports`).
//!
//! Capture and fork both seal the rootfs: freeze its host mount, turn the
//! writable upper into a read-only layer the live device restacks onto, and
//! thaw. Fork children stack their own uppers on that layer (see
//! [`layers`]).
//!
//! Drives (volumes and attached drives) are OverlayBD devices mounted on the
//! host under the work directory and bound into the container. Volume
//! snapshots freeze the host mount, seal the writable upper as Firecracker
//! does, and thaw it.

mod bundle;
mod guest;
mod layers;
mod logfile;
mod netns;
mod runtime;
mod subpath;

use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uvm_ublk_daemon::CreateOverlaybdRuntimeDeviceRequest;

use self::bundle::{BundleSpec, DriveBind};
use self::netns::GuestLink;
use self::runtime::OciRuntime;
use super::backend::{
    CapturedRootfs, CapturedSandboxSnapshot, PausedSandboxState, SandboxBackend,
    SandboxBackendFactory, SandboxCaptureError, SandboxCaptureResult, SandboxForkResult,
    SandboxForkSpec, SandboxRuntimeInfo,
};
use super::envd::EnvdInstance;
use super::extra_drive::{prepare_extra_drives, ExtraDrivePrepareMode};
use super::firecracker::restack_snapshot_overlaybd_device;
use super::network::{NetworkManager, SlotLease};
use super::process::Executor;
use super::ublk::{OverlaybdRuntimeHandle, SharedReadOnlyDevice, UblkCreateSpec, UblkDevice};
use super::{
    resolve_tools_image, CustomExtensionParams, EnvdAccessToken, EnvdApi, FreshSandboxBuildSpec,
    SandboxExecutor, SandboxLaunchConfig, SandboxNetworkPolicy, UblkDeviceManager,
};
use crate::cfg::{AppConfig, ConfigManager};
use crate::snapshot::{RunnableSnapshot, SandboxSnapshotManifest};
use crate::types::{ExtraDrive, RuntimeArtifactSet, SandboxId, SandboxResources};

/// Container names and cgroups carry this prefix, so startup reconciliation
/// only touches containers this server created.
const CONTAINER_PREFIX: &str = "aenv-";
const CGROUP_PARENT: &str = "/aenv-container";
const HOSTNAME: &str = "instance";
const DEFAULT_PIDS_LIMIT: u32 = 4096;
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Where container sandboxes keep their state, from the node config.
#[derive(Clone, Debug)]
struct ContainerPaths {
    /// One directory per sandbox: bundle, mounts, netns, log.
    work_base: PathBuf,
    /// The OCI runtime's state directory.
    runtime_root: PathBuf,
    /// Sealed rootfs layers shared by a sandbox and its forks.
    layers_base: PathBuf,
}

impl ContainerPaths {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            work_base: config.home_path.join("container/sandboxes"),
            runtime_root: config.runtime_path.join("container/runtime"),
            layers_base: config.home_path.join("container/layers"),
        }
    }
}

pub struct ContainerSandboxFactory {
    runtime: OciRuntime,
    paths: ContainerPaths,
}

impl ContainerSandboxFactory {
    pub fn from_config(config: &AppConfig) -> Self {
        let paths = ContainerPaths::from_config(config);
        Self {
            runtime: OciRuntime::new(config.container.runtime.clone(), &paths.runtime_root),
            paths,
        }
    }

    /// Removes containers, network namespaces and mounts left by a previous
    /// run of this server. Call before serving requests: container sandboxes
    /// do not survive a restart.
    pub async fn reconcile(&self) -> Result<()> {
        let mut failures = Vec::new();
        for id in self.runtime.list().await? {
            if !id.starts_with(CONTAINER_PREFIX) {
                continue;
            }
            info!(container = %id, "removing container left by a previous run");
            if let Err(err) = self.runtime.delete(&id).await {
                failures.push(format!("{id}: {err:#}"));
            }
        }
        let entries = match std::fs::read_dir(&self.paths.work_base) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return finish(failures),
            Err(err) => return Err(err).context("read container work directory"),
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            info!(work_dir = %dir.display(), "removing container work directory left by a previous run");
            if let Err(err) = remove_work_dir(&dir) {
                failures.push(format!("{}: {err:#}", dir.display()));
            }
        }
        // No sandbox stacks on a sealed layer once every work directory is gone.
        if failures.is_empty() {
            match std::fs::remove_dir_all(&self.paths.layers_base) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => failures.push(format!("remove sealed layers: {err}")),
            }
        }
        finish(failures)
    }
}

fn finish(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("container reconciliation: {}", failures.join("; "))
    }
}

/// Unmounts everything under a sandbox work directory and removes it.
fn remove_work_dir(dir: &Path) -> Result<()> {
    netns::remove_netns(&dir.join("netns"))?;
    if let Ok(binds) = std::fs::read_dir(dir.join("binds")) {
        for bind in binds.flatten() {
            unmount(&bind.path())?;
        }
    }
    if let Ok(drives) = std::fs::read_dir(dir.join("drives")) {
        for drive in drives.flatten() {
            if is_mount_point(&drive.path())? {
                thaw(&drive.path());
            }
            unmount(&drive.path())?;
        }
    }
    for mount_point in ["tools", "rootfs"] {
        unmount(&dir.join(mount_point))?;
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", dir.display())),
    }
}

/// Whether `path` is a mount point in this mount namespace.
fn is_mount_point(path: &Path) -> Result<bool> {
    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    let mounted = mount_points(&mountinfo).any(|point| Path::new(&point) == path);
    Ok(mounted)
}

/// Mount points listed in a mountinfo file, with octal escapes decoded.
fn mount_points(mountinfo: &str) -> impl Iterator<Item = String> + '_ {
    mountinfo.lines().filter_map(|line| {
        let escaped = line.split(' ').nth(4)?;
        let mut point = String::with_capacity(escaped.len());
        let mut rest = escaped;
        while let Some(index) = rest.find('\\') {
            point.push_str(&rest[..index]);
            let code = rest.get(index + 1..index + 4)?;
            point.push(u8::from_str_radix(code, 8).ok()? as char);
            rest = &rest[index + 4..];
        }
        point.push_str(rest);
        Some(point)
    })
}

/// Unmounts every mount stacked on `path`. Not mounted is success.
fn unmount(path: &Path) -> Result<()> {
    while is_mount_point(path)? {
        match umount2(path, MntFlags::empty()) {
            Ok(()) => {}
            Err(nix::errno::Errno::EBUSY) => {
                warn!(path = %path.display(), "mount busy; detaching");
                umount2(path, MntFlags::MNT_DETACH)
                    .with_context(|| format!("detach {}", path.display()))?;
            }
            Err(err) => bail!("unmount {}: {err}", path.display()),
        }
    }
    Ok(())
}

fn mount_ext4(device: &Path, target: &Path, read_only: bool) -> Result<()> {
    std::fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    let mut flags = MsFlags::MS_NOATIME | MsFlags::MS_NODEV;
    if read_only {
        flags |= MsFlags::MS_RDONLY;
    }
    // A read-only mount must not replay the journal: that would write to a
    // device other sandboxes may share.
    let data = read_only.then_some("noload");
    mount(Some(device), target, Some("ext4"), flags, data)
        .with_context(|| format!("mount {} on {}", device.display(), target.display()))
}

const FIFREEZE: libc::c_ulong = 0xC004_5877;
const FITHAW: libc::c_ulong = 0xC004_5878;

/// FIFREEZE/FITHAW on the filesystem mounted at `mount_point`.
fn freeze_ioctl(mount_point: &Path, request: libc::c_ulong) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(mount_point)?;
    let mut arg: libc::c_int = 0;
    // SAFETY: FIFREEZE/FITHAW take an int argument the kernel ignores, and
    // `dir` keeps the descriptor open for the call.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), request as _, &mut arg) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn freeze(mount_point: &Path) -> Result<()> {
    freeze_ioctl(mount_point, FIFREEZE).with_context(|| format!("freeze {}", mount_point.display()))
}

/// Thaws `mount_point`; not frozen (EINVAL) is success.
fn thaw(mount_point: &Path) -> bool {
    match freeze_ioctl(mount_point, FITHAW) {
        Ok(()) => true,
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => true,
        Err(err) => {
            warn!(mount = %mount_point.display(), error = %err, "thaw failed");
            false
        }
    }
}

fn sync_filesystem(mount_point: &Path) -> Result<()> {
    let dir = std::fs::File::open(mount_point)
        .with_context(|| format!("open {}", mount_point.display()))?;
    nix::unistd::syncfs(&dir).with_context(|| format!("syncfs {}", mount_point.display()))
}

/// A drive attached to a container sandbox.
struct AttachedDrive {
    drive: ExtraDrive,
    runtime: OverlaybdRuntimeHandle,
    /// The device's attachment path in the work directory.
    device: PathBuf,
    /// Host mount point under `drives/`, once mounted.
    host_mount: Option<PathBuf>,
    /// The pinned `subPath` under `binds/`, once bound.
    bind: Option<PathBuf>,
    /// Whether the device has been released.
    released: bool,
}

/// The capture failure to report once the caller tried to resume writes.
/// A terminal error stays terminal; a failed thaw makes any error terminal,
/// since writes are left stopped.
fn capture_failure(err: SandboxCaptureError, thawed: Result<()>) -> SandboxCaptureError {
    match thawed {
        Ok(()) => err,
        Err(thaw_err) => SandboxCaptureError::terminal(anyhow!("{err}; {thaw_err:#}")),
    }
}

impl AttachedDrive {
    /// Persistent volumes the sandbox can write, which volume snapshots seal.
    fn is_writable_volume(&self) -> bool {
        !self.drive.read_only() && self.drive.snapshot_output_dir().is_some()
    }
}

impl SandboxBackendFactory for ContainerSandboxFactory {
    fn build(
        &self,
        build_spec: FreshSandboxBuildSpec,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("the container backend requires the server to run as root");
        }
        Ok(Box::new(ContainerSandbox::new(
            build_spec,
            launch_config,
            self.runtime.clone(),
            &self.paths,
            layers::LayerRefs::default(),
        )))
    }

    fn build_from_snapshot(
        &self,
        _snapshot: &RunnableSnapshot,
        _launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        bail!("container sandboxes cannot be launched from snapshots")
    }

    fn decode_paused_state(
        &self,
        _artifact_root: PathBuf,
        _state: Value,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        bail!("container sandboxes cannot be paused")
    }

    fn build_from_paused_state(
        &self,
        _sandbox_id: SandboxId,
        _state: &dyn PausedSandboxState,
        _envd_access_token: Option<EnvdAccessToken>,
    ) -> Result<Box<dyn SandboxBackend>> {
        bail!("container sandboxes cannot be paused")
    }
}

/// Exit of the runtime process, published once it has been reaped.
type ExitState = Option<String>;

pub struct ContainerSandbox {
    id: SandboxId,
    container_id: String,
    build_spec: FreshSandboxBuildSpec,
    launch: SandboxLaunchConfig,
    runtime: OciRuntime,
    paths: ContainerPaths,
    work_dir: PathBuf,
    resources: SandboxResources,
    custom_extension_params: Option<CustomExtensionParams>,
    network_policy: Option<SandboxNetworkPolicy>,
    // Runtime state, released by `stop` in reverse order of acquisition.
    tools: Option<SharedReadOnlyDevice>,
    rootfs: Option<UblkDevice>,
    rootfs_image_config: Option<PathBuf>,
    rootfs_virtual_size: Option<u64>,
    mounts: Vec<PathBuf>,
    drives: Vec<AttachedDrive>,
    /// Volume mounts frozen by `freeze_and_snapshot_volumes`.
    frozen: Vec<PathBuf>,
    slot: Option<SlotLease>,
    guest_netns: Option<PathBuf>,
    exited: Option<watch::Receiver<ExitState>>,
    envd: Option<EnvdInstance>,
    last_cpu: guest::CpuSample,
    /// Sealed layers this sandbox's rootfs stacks on.
    layers: layers::LayerRefs,
    /// The rootfs sealed with the volumes for the fork that follows.
    pending_fork_rootfs: Option<PathBuf>,
}

impl ContainerSandbox {
    fn new(
        build_spec: FreshSandboxBuildSpec,
        launch: SandboxLaunchConfig,
        runtime: OciRuntime,
        paths: &ContainerPaths,
        layers: layers::LayerRefs,
    ) -> Self {
        let id = launch.sandbox_id;
        Self {
            id,
            container_id: format!("{CONTAINER_PREFIX}{id}"),
            resources: build_spec.resources,
            custom_extension_params: launch.custom_extension_params.clone(),
            network_policy: launch.network.clone(),
            work_dir: paths.work_base.join(id.to_string()),
            paths: paths.clone(),
            build_spec,
            launch,
            runtime,
            tools: None,
            rootfs: None,
            rootfs_image_config: None,
            rootfs_virtual_size: None,
            mounts: Vec::new(),
            drives: Vec::new(),
            frozen: Vec::new(),
            slot: None,
            guest_netns: None,
            exited: None,
            envd: None,
            last_cpu: Default::default(),
            layers,
            pending_fork_rootfs: None,
        }
    }

    /// Seals the rootfs into a new shared layer directory and returns the
    /// image config of the sealed stack. The sandbox keeps running on it.
    /// Seals the rootfs: freeze, restack, thaw.
    async fn seal_rootfs(&mut self) -> SandboxCaptureResult<PathBuf> {
        let rootfs_mount = self.work_dir.join("rootfs");
        sync_filesystem(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
        freeze(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
        self.frozen.push(rootfs_mount);
        let sealed = self.restack_rootfs().await;
        let thawed = self.thaw_frozen();
        match sealed {
            Ok(image_config) => thawed
                .map(|()| image_config)
                .map_err(SandboxCaptureError::terminal),
            Err(err) => Err(capture_failure(err, thawed)),
        }
    }

    /// Restacks the rootfs, whose filesystem the caller has frozen, onto a
    /// new sealed layer and returns the sealed stack's image config.
    async fn restack_rootfs(&mut self) -> SandboxCaptureResult<PathBuf> {
        let device = self
            .rootfs
            .clone()
            .context("container has no rootfs device")
            .map_err(SandboxCaptureError::recoverable)?;
        let live_config = self
            .rootfs_image_config
            .clone()
            .context("container has no rootfs image config")
            .map_err(SandboxCaptureError::recoverable)?;
        let layer_dir = self
            .paths
            .layers_base
            .join(uuid::Uuid::now_v7().simple().to_string());
        let sealed = restack_snapshot_overlaybd_device(
            &device,
            false,
            &live_config,
            &layer_dir,
            "rootfs.commit",
            "rootfs",
        )
        .await;
        match sealed {
            Ok(image_config) => {
                // The live device now stacks on the sealed layer.
                self.layers.add(layer_dir);
                Ok(image_config)
            }
            Err(err) => {
                let err = SandboxCaptureError::from(err);
                if err.is_terminal() {
                    // The device may already stack on the new layer: keep it
                    // until the device is gone.
                    self.layers.add(layer_dir);
                } else {
                    let _ = std::fs::remove_dir_all(&layer_dir);
                }
                Err(err)
            }
        }
    }

    /// A child stacked on the sealed `image_config`: the parent's files,
    /// shared read-only drives and the child's own volumes, fresh processes.
    fn fork_child(&self, image_config: &Path, spec: &SandboxForkSpec) -> ContainerSandbox {
        let mut extra_drives: Vec<ExtraDrive> = self
            .build_spec
            .extra_drives
            .iter()
            .filter(|drive| !drive.is_volume())
            .cloned()
            .collect();
        extra_drives.extend(spec.extra_drives.iter().cloned());
        let build_spec = FreshSandboxBuildSpec {
            backend: self.build_spec.backend,
            image_config_path: image_config.to_path_buf(),
            context: self.build_spec.context.clone(),
            resources: self.resources,
            extra_drives,
            extra_boot_args: None,
        };
        let launch = SandboxLaunchConfig {
            sandbox_id: spec.sandbox_id,
            snapshot_id: self.launch.snapshot_id.clone(),
            env_vars: self.launch.env_vars.clone(),
            network: self.network_policy.clone(),
            custom_extension_params: self.custom_extension_params.clone(),
            envd_access_token: spec.envd_access_token.clone(),
            ..Default::default()
        };
        ContainerSandbox::new(
            build_spec,
            launch,
            self.runtime.clone(),
            &self.paths,
            self.layers.inherit(),
        )
    }

    fn log_path(&self) -> PathBuf {
        self.work_dir.join("container.log")
    }

    /// `cgroupsPath` in the bundle, relative to this server's cgroup root.
    fn cgroups_path(&self) -> String {
        format!("{CGROUP_PARENT}/{}", self.container_id)
    }

    fn cgroup_dir(&self) -> PathBuf {
        PathBuf::from(format!("/sys/fs/cgroup{}", self.cgroups_path()))
    }

    async fn attach_storage(&mut self, config: &AppConfig) -> Result<()> {
        let global_config = config.ublk.overlaybd.global_config_path.clone();
        let tools_config = resolve_tools_image(config, config.resolved_tools_version())
            .await?
            .context("the container backend needs an OverlayBD tools image")?;
        let tools = UblkDeviceManager::global()
            .get_or_create_shared_tools(&UblkCreateSpec::Overlaybd {
                image_config: tools_config,
                global_config: global_config.clone(),
            })
            .await
            .context("attach tools drive")?;
        let tools_device = tools.device_path().to_path_buf();
        self.tools = Some(tools);

        let requested_virtual_size = match self.resources.disk_size_mib {
            0 => None,
            mib => Some(
                u64::from(mib)
                    .checked_mul(1024 * 1024)
                    .context("requested rootfs size overflows bytes")?,
            ),
        };
        let rootfs = UblkDeviceManager::global()
            .create_overlaybd_runtime_device(CreateOverlaybdRuntimeDeviceRequest {
                source_image_config: &self.build_spec.image_config_path,
                global_config: &global_config,
                runtime_dir: &self.work_dir.join("overlaybd"),
                read_only: false,
                runtime_upper_mode: config.ublk.overlaybd.runtime_upper_mode,
                requested_virtual_size,
                known_source_virtual_size: None,
                allow_shrink: config.ublk.overlaybd.allow_shrink,
            })
            .await
            .context("create rootfs device")?;
        let rootfs_device = rootfs.device.device_path().to_path_buf();
        self.rootfs_virtual_size = Some(rootfs.actual_virtual_size);
        self.rootfs_image_config = Some(rootfs.image_config_path);
        self.rootfs = Some(rootfs.device);

        let rootfs_dir = self.work_dir.join("rootfs");
        mount_ext4(&rootfs_device, &rootfs_dir, false)?;
        self.mounts.push(rootfs_dir);
        let tools_dir = self.work_dir.join("tools");
        mount_ext4(&tools_device, &tools_dir, true)?;
        self.mounts.push(tools_dir);
        self.attach_drives(config, &global_config).await
    }

    /// Creates a device per volume or attached drive and mounts it on the
    /// host; the bundle binds each mount into the container.
    async fn attach_drives(&mut self, config: &AppConfig, global_config: &Path) -> Result<()> {
        let drives = self.build_spec.extra_drives.clone();
        if drives.is_empty() {
            return Ok(());
        }
        let allow_shrink = config.ublk.overlaybd.allow_shrink;
        let (attachments, runtimes) = prepare_extra_drives(
            &drives,
            global_config,
            &self.work_dir,
            config.ublk.overlaybd.runtime_upper_mode,
            |_| ExtraDrivePrepareMode::Fresh { allow_shrink },
        )
        .await
        .context("prepare drives")?
        .into_parts();
        // Record every device before mounting any, so `stop` releases all of
        // them whichever mount fails.
        for ((drive, attachment), runtime) in drives.into_iter().zip(attachments).zip(runtimes) {
            self.drives.push(AttachedDrive {
                device: self.work_dir.join(&attachment.attachment_path),
                drive,
                runtime,
                host_mount: None,
                bind: None,
                released: false,
            });
        }
        for index in 0..self.drives.len() {
            let drive_id = self.drives[index].drive.drive_id().to_owned();
            super::failpoint::fail("container-mount-drive", Some(&drive_id))?;
            let host_mount = self.work_dir.join("drives").join(&drive_id);
            let attached = &mut self.drives[index];
            mount_ext4(&attached.device, &host_mount, attached.drive.read_only())?;
            attached.host_mount = Some(host_mount.clone());
            if let Some(sub_path) = attached.drive.sub_path().map(Path::to_path_buf) {
                let pinned = subpath::open_beneath(&host_mount, &sub_path)
                    .with_context(|| format!("drive '{drive_id}' subPath"))?;
                let target = self.work_dir.join("binds").join(&drive_id);
                subpath::pin(&pinned, &target)?;
                attached.bind = Some(target);
            }
        }
        Ok(())
    }

    /// Unbinds, unmounts and releases one drive. Each step is recorded, so a
    /// failed release can be retried by the next `stop`.
    async fn release_drive(attached: &mut AttachedDrive) -> Result<()> {
        if let Some(bind) = &attached.bind {
            unmount(bind)?;
            attached.bind = None;
        }
        if let Some(host_mount) = &attached.host_mount {
            unmount(host_mount)?;
            attached.host_mount = None;
        }
        if !attached.released {
            UblkDeviceManager::global()
                .release_device(&attached.runtime.device)
                .await
                .with_context(|| format!("release drive '{}'", attached.drive.drive_id()))?;
            attached.released = true;
        }
        Ok(())
    }

    fn drive_binds(&self) -> Vec<DriveBind> {
        self.drives
            .iter()
            .filter_map(|attached| {
                // A subPath binds from its pinned staging mount, never from a
                // path looked up inside the drive.
                let source = match (&attached.bind, attached.drive.sub_path()) {
                    (Some(bind), Some(_)) => bind.clone(),
                    (None, Some(_)) => return None,
                    (_, None) => attached.host_mount.clone()?,
                };
                Some(DriveBind {
                    source,
                    destination: attached.drive.mount_path().to_path_buf(),
                    read_only: attached.drive.read_only(),
                })
            })
            .collect()
    }

    /// Seals the writable volumes, whose filesystems the caller has frozen.
    async fn seal_volumes(&self) -> Result<()> {
        for attached in self
            .drives
            .iter()
            .filter(|attached| attached.is_writable_volume())
        {
            let output_dir = attached
                .drive
                .snapshot_output_dir()
                .expect("writable volumes have an output directory");
            let layer = format!("snapshot-{}.commit", uuid::Uuid::now_v7().simple());
            restack_snapshot_overlaybd_device(
                &attached.runtime.device,
                false,
                &attached.runtime.image_config_path,
                output_dir,
                &layer,
                "volume",
            )
            .await
            .with_context(|| format!("snapshot volume '{}'", attached.drive.drive_id()))?;
        }
        Ok(())
    }

    fn writable_volume_mounts(&self) -> Vec<PathBuf> {
        self.drives
            .iter()
            .filter(|attached| attached.is_writable_volume())
            .filter_map(|attached| attached.host_mount.clone())
            .collect()
    }

    /// Freezes the writable volumes and records them as frozen.
    fn freeze_volumes(&mut self) -> Result<()> {
        for mount in self.writable_volume_mounts() {
            sync_filesystem(&mount)?;
            freeze(&mount)?;
            self.frozen.push(mount);
        }
        Ok(())
    }

    fn thaw_frozen(&mut self) -> Result<()> {
        while let Some(mount) = self.frozen.last() {
            if !thaw(mount) {
                bail!("thaw {}", mount.display());
            }
            self.frozen.pop();
        }
        Ok(())
    }

    async fn attach_network(&mut self) -> Result<GuestLink> {
        let slot = NetworkManager::global()
            .allocate_configured(self.network_policy.clone())
            .await
            .context("allocate network slot")?;
        let (tap_ip, guest_ip, prefix) = slot.guest_link();
        let link = GuestLink {
            tap_ip,
            guest_ip,
            prefix,
        };
        let slot_netns = slot.namespace_path();
        self.slot = Some(slot);

        let guest_netns = self.work_dir.join("netns");
        self.guest_netns = Some(guest_netns.clone());
        tokio::task::spawn_blocking(move || {
            netns::create_netns(&guest_netns)?;
            netns::attach_guest(&slot_netns, &guest_netns, link)
        })
        .await
        .context("join container network setup")??;
        Ok(link)
    }

    fn start_runtime(&mut self) -> Result<()> {
        let mut child = self.runtime.run(&self.work_dir, &self.container_id)?;
        let log = logfile::LogFile::new(self.log_path());
        if let Some(stdout) = child.stdout.take() {
            logfile::spawn_pump(stdout, Arc::clone(&log));
        }
        if let Some(stderr) = child.stderr.take() {
            logfile::spawn_pump(stderr, log);
        }
        let (tx, rx) = watch::channel(None);
        let container = self.container_id.clone();
        tokio::spawn(async move {
            let exit = match child.wait().await {
                Ok(status) => status.to_string(),
                Err(err) => format!("wait failed: {err}"),
            };
            debug!(container = %container, %exit, "container runtime exited");
            let _ = tx.send(Some(exit));
        });
        self.exited = Some(rx);
        Ok(())
    }

    async fn start_inner(&mut self) -> Result<()> {
        let config = ConfigManager::global_config();
        std::fs::create_dir_all(&self.work_dir)
            .with_context(|| format!("create {}", self.work_dir.display()))?;
        self.attach_storage(config).await?;
        let link = self.attach_network().await?;
        let dns = self
            .slot
            .as_ref()
            .map(|slot| slot.guest_dns_server())
            .context("network slot missing")?;
        let cgroups_path = self.cgroups_path();
        bundle::write_bundle(&BundleSpec {
            work_dir: &self.work_dir,
            hostname: HOSTNAME,
            guest_ip: link.guest_ip,
            nameservers: &[dns],
            resources: self.resources,
            pids_limit: DEFAULT_PIDS_LIMIT,
            envd_port: config.tools.control_plane_port,
            cgroups_path: &cgroups_path,
            drives: &self.drive_binds(),
        })?;
        self.start_runtime()?;

        let host_ip = self.host_interaction_ip().context("network slot missing")?;
        self.envd = Some(EnvdInstance::new(
            format!("http://{host_ip}:{}", config.tools.control_plane_port),
            self.launch.envd_access_token.clone(),
        ));
        info!(container = %self.container_id, work_dir = %self.work_dir.display(), "container started");
        Ok(())
    }

    async fn ready_inner(&self) -> Result<()> {
        let config = ConfigManager::global_config();
        let envd = self.envd.as_ref().context("container has not started")?;
        let mut exited = self.exited.clone().context("container has not started")?;
        let ready = envd.wait_for_ready(
            Duration::from_secs(config.envd.init_timeout_secs),
            Duration::from_millis(config.envd.poll_ms),
        );
        tokio::select! {
            result = ready => result?,
            changed = exited.wait_for(Option::is_some) => {
                let exit = changed
                    .map(|exit| exit.clone().unwrap_or_default())
                    .unwrap_or_else(|_| "unknown".to_owned());
                bail!(
                    "container exited before envd was ready ({exit}); see {}",
                    self.log_path().display()
                );
            }
        }
        for device_key in [
            self.tools
                .as_ref()
                .map(|tools| tools.image_config_path().to_path_buf()),
            self.rootfs_image_config.clone(),
        ]
        .into_iter()
        .flatten()
        {
            UblkDeviceManager::global()
                .notify_sandbox_ready(&device_key)
                .await;
        }

        let context = &self.build_spec.context;
        let mut env_vars: HashMap<String, String> = context.env_vars.clone();
        if let Some(launch_env) = &self.launch.env_vars {
            env_vars.extend(launch_env.clone());
        }
        envd.init(
            (!env_vars.is_empty()).then_some(env_vars),
            Some(context.workdir.clone()),
            context.user.clone(),
        )
        .await
        .context("initialize envd")
    }

    async fn stop_inner(&mut self) -> Result<()> {
        if let Some(envd) = self.envd.take() {
            envd.invalidate();
        }
        let mut failures = Vec::new();
        if let Some(mut exited) = self.exited.take() {
            if exited.borrow().is_none() {
                if let Err(err) = self.runtime.kill(&self.container_id, "KILL").await {
                    failures.push(format!("kill: {err:#}"));
                }
                if tokio::time::timeout(STOP_TIMEOUT, exited.wait_for(Option::is_some))
                    .await
                    .is_err()
                {
                    failures.push(format!(
                        "container did not exit within {}s",
                        STOP_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        if let Err(err) = self.runtime.delete(&self.container_id).await {
            failures.push(format!("delete: {err:#}"));
        }
        if let Some(path) = self.guest_netns.take() {
            if let Err(err) = netns::remove_netns(&path) {
                failures.push(format!("{err:#}"));
            }
        }
        if let Some(slot) = self.slot.take() {
            // The slot's tap0 is now a veth; never pool it.
            match tokio::task::spawn_blocking(move || slot.destroy(false)).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => failures.push(format!("destroy network slot: {err:#}")),
                Err(err) => failures.push(format!("join slot teardown: {err}")),
            }
        }
        if let Err(err) = self.thaw_frozen() {
            failures.push(format!("{err:#}"));
        }
        let mut kept = Vec::new();
        while let Some(mut attached) = self.drives.pop() {
            if let Err(err) = Self::release_drive(&mut attached).await {
                failures.push(format!("{err:#}"));
                kept.push(attached);
            }
        }
        kept.reverse();
        self.drives = kept;
        while let Some(path) = self.mounts.pop() {
            if let Err(err) = unmount(&path) {
                failures.push(format!("{err:#}"));
            }
        }
        if let Some(device) = self.rootfs.take() {
            if let Err(err) = UblkDeviceManager::global().delete_device(&device).await {
                failures.push(format!("delete rootfs device: {err:#}"));
                // Keep it, and the layers under it, for the next attempt.
                self.rootfs = Some(device);
            }
        }
        if let Some(tools) = self.tools.take() {
            if let Err(err) = tools.release().await {
                failures.push(format!("release tools drive: {err:#}"));
            }
        }
        if self.rootfs.is_none() {
            // Nothing of this sandbox stacks on its sealed layers any more.
            self.layers.release();
        }
        if failures.is_empty() {
            if let Err(err) = std::fs::remove_dir_all(&self.work_dir) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("remove work directory: {err}"));
                }
            }
        }
        if failures.is_empty() {
            debug!(container = %self.container_id, "container stopped");
            Ok(())
        } else {
            Err(anyhow!(
                "stop container {}: {}",
                self.container_id,
                failures.join("; ")
            ))
        }
    }

    fn unsupported<T>(&self, operation: &str) -> Result<T> {
        bail!("container sandbox {} does not support {operation}", self.id)
    }
}

#[async_trait]
impl SandboxBackend for ContainerSandbox {
    /// Metrics and logs come from the host side (cgroup, rootfs, runtime
    /// log); see [`guest`].
    fn envd(&self) -> Option<Arc<dyn EnvdApi>> {
        self.envd.as_ref()?;
        Some(Arc::new(guest::ContainerGuest {
            cgroup: self.cgroup_dir(),
            rootfs: self.work_dir.join("rootfs"),
            log: self.log_path(),
            cpu_count: self.resources.cpu_count,
            last_cpu: Arc::clone(&self.last_cpu),
        }))
    }

    async fn start(&mut self) -> Result<()> {
        self.start_nowait().await?;
        self.wait_for_ready().await
    }

    async fn start_nowait(&mut self) -> Result<()> {
        self.start_inner().await
    }

    async fn wait_for_ready(&self) -> Result<()> {
        self.ready_inner().await
    }

    async fn pause(
        &mut self,
        _artifact_root: Option<&Path>,
    ) -> SandboxCaptureResult<Arc<dyn PausedSandboxState>> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be paused"
        )))
    }

    async fn resume(&mut self) -> Result<()> {
        self.unsupported("resume")
    }

    async fn snapshot(&mut self) -> SandboxCaptureResult<CapturedSandboxSnapshot> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be snapshotted"
        )))
    }

    /// Volume snapshots of a running container precede only a fork, so the
    /// rootfs is sealed in the same frozen window and kept for that fork:
    /// children get volumes and a rootfs from one point in time.
    async fn snapshot_volumes(&mut self) -> SandboxCaptureResult<()> {
        self.pending_fork_rootfs = None;
        let result = async {
            self.freeze_volumes()
                .map_err(SandboxCaptureError::recoverable)?;
            let rootfs_mount = self.work_dir.join("rootfs");
            sync_filesystem(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
            freeze(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
            self.frozen.push(rootfs_mount);
            self.seal_volumes()
                .await
                .map_err(SandboxCaptureError::from)?;
            self.restack_rootfs().await
        }
        .await;
        let thawed = self.thaw_frozen();
        match result {
            Ok(image_config) => {
                thawed.map_err(SandboxCaptureError::terminal)?;
                self.pending_fork_rootfs = Some(image_config);
                Ok(())
            }
            Err(err) => Err(capture_failure(err, thawed)),
        }
    }

    /// Filesystem-only fork: seal the rootfs once and start each child on its
    /// own upper over the sealed layer. Children start fresh processes.
    async fn fork(
        &mut self,
        spec: &[SandboxForkSpec],
    ) -> SandboxCaptureResult<Vec<SandboxForkResult>> {
        if let Some(attached) = self
            .drives
            .iter()
            .find(|attached| !attached.drive.read_only() && !attached.drive.is_volume())
        {
            return Err(SandboxCaptureError::recoverable(anyhow!(
                "cannot fork a container sandbox with writable attached drive '{}'",
                attached.drive.drive_id()
            )));
        }
        let image_config = match self.pending_fork_rootfs.take() {
            // Sealed together with the volumes the API forked for children.
            Some(image_config) => image_config,
            None => self.seal_rootfs().await?,
        };
        let children: Vec<_> = spec
            .iter()
            .map(|child| self.fork_child(&image_config, child))
            .collect();
        let started = futures::future::join_all(children.into_iter().map(|mut child| async move {
            match child.start().await {
                Ok(()) => Ok(Box::new(child) as Box<dyn SandboxBackend>),
                Err(err) => {
                    if let Err(stop_err) = child.stop().await {
                        warn!(error = %format_args!("{stop_err:#}"), "failed to stop fork child after start failure");
                    }
                    Err(err.context("start forked container"))
                }
            }
        }))
        .await;
        Ok(started)
    }

    async fn capture_rootfs(&mut self) -> SandboxCaptureResult<CapturedRootfs> {
        let image_config = self.seal_rootfs().await?;
        // The publisher keeps the sealed layers even if this sandbox goes.
        Ok(CapturedRootfs::new(
            image_config,
            layers::LayerHold::new(self.layers.inherit()),
        ))
    }

    async fn capture_to_dir(
        &mut self,
        _at: &Path,
    ) -> SandboxCaptureResult<(SandboxSnapshotManifest, Option<Box<dyn Any + Send>>)> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be captured"
        )))
    }

    async fn stop(&mut self) -> Result<()> {
        self.stop_inner().await
    }

    async fn freeze_and_snapshot_volumes(&mut self) -> SandboxCaptureResult<()> {
        let result = match self.freeze_volumes() {
            Ok(()) => self.seal_volumes().await.map_err(SandboxCaptureError::from),
            Err(err) => Err(SandboxCaptureError::recoverable(err)),
        };
        if let Err(err) = result {
            // A recoverable error must leave writes resumed; a terminal one
            // stays terminal whether or not the thaw works.
            let thawed = self.thaw_frozen();
            return Err(capture_failure(err, thawed));
        }
        Ok(())
    }

    async fn thaw_volumes(&mut self) -> Result<()> {
        self.thaw_frozen()
    }

    fn host_interaction_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.slot.as_ref().map(|slot| slot.host_interaction_ip)
    }

    fn runtime_info(&self) -> SandboxRuntimeInfo {
        let paths = [
            self.tools
                .as_ref()
                .map(|tools| tools.image_config_path().to_path_buf()),
            self.rootfs_image_config.clone(),
        ]
        .into_iter()
        .flatten()
        .chain(
            self.drives
                .iter()
                .map(|attached| attached.runtime.image_config_path.clone()),
        )
        .collect();
        SandboxRuntimeInfo {
            rootfs_virtual_size: self.rootfs_virtual_size,
            runtime_artifacts: RuntimeArtifactSet::from_overlaybd_image_configs(paths),
        }
    }

    fn startup_artifacts(&self) -> RuntimeArtifactSet {
        let mut paths = vec![self.build_spec.image_config_path.clone()];
        paths.extend(
            self.build_spec
                .extra_drives
                .iter()
                .map(|drive| drive.image_config_path().to_path_buf()),
        );
        RuntimeArtifactSet::from_overlaybd_image_configs(paths)
    }

    async fn update_network_policy(&mut self, policy: Option<SandboxNetworkPolicy>) -> Result<()> {
        match self.slot.as_mut() {
            Some(slot) => {
                slot.set_egress_policy(policy.as_ref())
                    .context("configure sandbox network policy")?;
            }
            None if policy.is_some() => bail!("sandbox has no active network slot"),
            None => {}
        }
        self.network_policy = policy;
        Ok(())
    }

    fn update_custom_extension_params(&mut self, params: Option<CustomExtensionParams>) {
        self.custom_extension_params = params;
    }
}

#[async_trait(?Send)]
impl SandboxExecutor for ContainerSandbox {
    fn executor(&self) -> Result<Executor> {
        let envd = self.envd.as_ref().context("Sandbox is not running")?;
        Ok(Executor::new(envd.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_points_decode_escapes() {
        let mountinfo = "36 35 98:0 /mnt1 /mnt/a\\040b rw,noatime master:1 - ext3 /dev/root rw\n\
                         37 35 98:0 / /work/x/rootfs rw - ext4 /dev/ublkb3 rw\n";
        let points: Vec<_> = mount_points(mountinfo).collect();
        assert_eq!(
            points,
            vec!["/mnt/a b".to_string(), "/work/x/rootfs".to_string()]
        );
    }

    #[tokio::test]
    async fn reconcile_without_state_is_a_no_op() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let factory = ContainerSandboxFactory {
            runtime: OciRuntime::new("runc", temp.path().join("missing-root")),
            paths: ContainerPaths {
                work_base: temp.path().join("missing-work"),
                runtime_root: temp.path().join("missing-root"),
                layers_base: temp.path().join("missing-layers"),
            },
        };
        factory.reconcile().await
    }

    #[tokio::test]
    async fn reconcile_removes_leftover_work_directories() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work_base = temp.path().join("sandboxes");
        let leftover = work_base.join("01a20000-0000-7000-8000-000000000000");
        std::fs::create_dir_all(leftover.join("rootfs"))?;
        std::fs::write(leftover.join("config.json"), "{}")?;
        let factory = ContainerSandboxFactory {
            runtime: OciRuntime::new("runc", temp.path().join("missing-root")),
            paths: ContainerPaths {
                work_base: work_base.clone(),
                runtime_root: temp.path().join("missing-root"),
                layers_base: temp.path().join("layers"),
            },
        };
        std::fs::create_dir_all(temp.path().join("layers/old"))?;
        factory.reconcile().await?;
        assert!(!leftover.exists());
        assert!(!temp.path().join("layers").exists());
        Ok(())
    }
}
