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
//! for publishing as an image, filesystem-only and full forks, pause, and
//! memory snapshots with launches from them. Template builds still need
//! Firecracker (`capture_to_dir`).
//!
//! Pause freezes the container, dumps its processes with CRIU and seals the
//! rootfs and drives into the paused sandbox's artifact root, all while the
//! processes stay frozen; `stop` then releases everything (see [`paused`]).
//! Resume builds a new sandbox on the sealed rootfs and drives, with a new
//! network slot and cgroup, and `runc restore`s the processes into it.
//!
//! A full fork dumps the processes once and restores the dump into every
//! child (see [`fork`]). A memory snapshot is captured the same way and
//! stored by the snapshot pipeline; sandboxes launched from it restore its
//! dump (see [`snapshot`]).
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
mod fork;
mod guest;
mod layers;
mod logfile;
mod netns;
mod paused;
mod runtime;
mod snapshot;
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
use self::paused::ContainerPausedState;
use self::runtime::OciRuntime;
use super::backend::{
    CapturedRootfs, CapturedSandboxSnapshot, PausedSandboxState, SandboxBackend,
    SandboxBackendFactory, SandboxCaptureError, SandboxCaptureResult, SandboxForkCapture,
    SandboxForkResult, SandboxForkSpec, SandboxRuntimeInfo, UnstoppedForkChild,
};
use super::envd::EnvdInstance;
use super::extra_drive::{prepare_extra_drives, ExtraDrivePrepareMode};
use super::firecracker::{
    restack_snapshot_overlaybd_device, stage_overlaybd_snapshot_from_live_runtime,
};
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
/// How often a resume checks whether CRIU has finished restoring.
const RESTORE_POLL: Duration = Duration::from_millis(10);
/// The first envd probe after a restore; later ones back off to the usual.
const RESTORE_FIRST_PROBE: Duration = Duration::from_millis(100);

/// Where container sandboxes keep their state, from the node config.
#[derive(Clone, Debug)]
struct ContainerPaths {
    /// One directory per sandbox: bundle, mounts, netns, log.
    work_base: PathBuf,
    /// The OCI runtime's state directory.
    runtime_root: PathBuf,
    /// Sealed rootfs layers shared by a sandbox and its forks.
    layers_base: PathBuf,
    /// Process dumps of full forks, each kept while its children restore.
    captures_base: PathBuf,
}

impl ContainerPaths {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            work_base: config.home_path.join("container/sandboxes"),
            runtime_root: config.runtime_path.join("container/runtime"),
            layers_base: sealed_layers_base(config),
            captures_base: config.home_path.join("container/fork-captures"),
        }
    }
}

/// Where sealed rootfs layers live. Startup reconciliation removes them, so
/// snapshots that outlive a restart adopt them into their own artifacts.
pub(crate) fn sealed_layers_base(config: &AppConfig) -> PathBuf {
    config.home_path.join("container/layers")
}

pub struct ContainerSandboxFactory {
    runtime: OciRuntime,
    paths: ContainerPaths,
}

impl ContainerSandboxFactory {
    /// Also records whether this node can pause container sandboxes, which
    /// decides what create, timeout and shutdown do with them.
    pub fn from_config(config: &AppConfig) -> Self {
        let paths = ContainerPaths::from_config(config);
        let runtime = config.container.runtime.clone();
        match pause_support(&runtime) {
            Ok(()) => crate::types::set_container_pause_available(true),
            Err(reason) => {
                warn!(runtime = %runtime, %reason, "container sandboxes cannot pause on this node; timeouts delete them");
                crate::types::set_container_pause_available(false);
            }
        }
        Self {
            runtime: OciRuntime::new(runtime, &paths.runtime_root),
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
        // No sandbox stacks on a sealed layer once every work directory is
        // gone, and no fork is restoring from a capture.
        if failures.is_empty() {
            for (dir, what) in [
                (&self.paths.layers_base, "sealed layers"),
                (&self.paths.captures_base, "fork captures"),
            ] {
                match std::fs::remove_dir_all(dir) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => failures.push(format!("remove {what}: {err}")),
                }
            }
        }
        finish(failures)
    }
}

/// Whether `runtime` can pause containers here: the dump and restore pass
/// runc's CRIU options (`--tcp-established`, `--file-locks`, a CRIU config
/// annotation), which runc and crun take and runsc does not, and CRIU must
/// be installed.
fn pause_support(runtime: &str) -> std::result::Result<(), String> {
    if !runtime_checkpoints_with_criu(runtime) {
        return Err(format!("{runtime} does not checkpoint with CRIU"));
    }
    match std::process::Command::new("criu").arg("--version").output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => return Err(format!("criu --version failed: {}", output.status)),
        Err(err) => return Err(format!("criu is not available: {err}")),
    }
    // crun links CRIU in as a library, loaded when it checkpoints.
    if Path::new(runtime)
        .file_name()
        .and_then(|name| name.to_str())
        == Some("crun")
    {
        let version = std::process::Command::new(runtime)
            .arg("--version")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .map_err(|err| format!("{runtime} --version: {err}"))?;
        if !version.contains("+CRIU") {
            return Err(format!("{runtime} was built without CRIU"));
        }
        let libraries = std::process::Command::new("ldconfig")
            .arg("-p")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .map_err(|err| format!("ldconfig -p: {err}"))?;
        if !libraries.contains("libcriu.so.2") {
            return Err(
                "libcriu.so.2, which crun loads to checkpoint, is not installed".to_owned(),
            );
        }
    }
    Ok(())
}

fn runtime_checkpoints_with_criu(runtime: &str) -> bool {
    matches!(
        Path::new(runtime)
            .file_name()
            .and_then(|name| name.to_str()),
        Some("runc" | "crun")
    )
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

/// Stages a copy of the sealed stack `sealed` into `output_dir`: its
/// sandbox-owned layers are hard-linked there, so the copy outlives the
/// sealed-layer directory, and the live device never depends on the copy.
async fn stage_into(sealed: &Path, output_dir: &Path) -> SandboxCaptureResult<PathBuf> {
    stage_overlaybd_snapshot_from_live_runtime(sealed, output_dir, None)
        .await
        .with_context(|| format!("stage {} into {}", sealed.display(), output_dir.display()))
        .map_err(SandboxCaptureError::recoverable)
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

    /// A new container that restores a container snapshot's processes: the
    /// snapshot's rootfs under a new upper, its attached drives and the
    /// launch's volumes at the dumped mount paths, and this sandbox's own
    /// identity and access token.
    fn build_from_snapshot(
        &self,
        snapshot: &RunnableSnapshot,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("the container backend requires the server to run as root");
        }
        let manifest = snapshot.manifest();
        let section = manifest.container.as_ref().with_context(|| {
            format!(
                "snapshot {} is a {} capture, not a container's",
                snapshot.record().id,
                manifest.backend
            )
        })?;
        if !runtime::same_executable(&section.runtime, self.runtime.binary()) {
            bail!(
                "snapshot {} was dumped by {} but this node runs {}",
                snapshot.record().id,
                section.runtime,
                self.runtime.binary()
            );
        }
        let extra_drives = snapshot::arrange_drives(
            section,
            &manifest.extra_drives(),
            &launch_config.extra_drives,
        )?;
        let build_spec = FreshSandboxBuildSpec {
            backend: crate::types::SandboxBackendKind::Container,
            image_config_path: manifest.rootfs.image_config_path.clone(),
            context: snapshot.committed().context.clone(),
            resources: section.resources,
            extra_drives,
            extra_boot_args: None,
        };
        let launch = SandboxLaunchConfig {
            extra_drives: Vec::new(),
            ..launch_config
        };
        let mut sandbox = ContainerSandbox::new(
            build_spec,
            launch,
            self.runtime.clone(),
            &self.paths,
            layers::LayerRefs::default(),
        );
        sandbox.restore = Some(Restore {
            criu_dir: sandbox.work_dir.join("criu-images"),
            tools: RestoreTools::Release(section.tools_version.clone()),
            rootfs_virtual_size: Some(manifest.rootfs.virtual_size),
            envd_port: section.envd_port,
            archive: Some(manifest.vm_state.path.clone()),
        });
        sandbox.auth_mount = section.auth_mount;
        sandbox.new_identity = true;
        sandbox.snapshot_hold = Some(snapshot.clone());
        Ok(Box::new(sandbox))
    }

    fn decode_paused_state(
        &self,
        _backend: crate::types::SandboxBackendKind,
        _artifact_root: PathBuf,
        state: Value,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        // A runtime mismatch is refused when resuming, not here: refusing at
        // load would discard a dump that a reconfigured node can still use.
        Ok(Arc::new(ContainerPausedState::decode(state)?))
    }

    /// A sandbox that rebuilds the paused one's devices, network and cgroup
    /// and restores its processes from the dump. envd gets a fresh token
    /// and the environment again once it answers.
    fn build_from_paused_state(
        &self,
        sandbox_id: SandboxId,
        state: &dyn PausedSandboxState,
        envd_access_token: Option<EnvdAccessToken>,
    ) -> Result<Box<dyn SandboxBackend>> {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("the container backend requires the server to run as root");
        }
        let state = state
            .downcast_ref::<ContainerPausedState>()
            .context("paused state is not a container's")?;
        if !runtime::same_executable(&state.runtime, self.runtime.binary()) {
            bail!(
                "paused container was dumped by {} but this node runs {}",
                state.runtime,
                self.runtime.binary()
            );
        }
        let build_spec = FreshSandboxBuildSpec {
            backend: crate::types::SandboxBackendKind::Container,
            image_config_path: state.rootfs_image_config.clone(),
            context: state.context.clone(),
            resources: state.resources,
            extra_drives: state.extra_drives.clone(),
            extra_boot_args: None,
        };
        let launch = SandboxLaunchConfig {
            sandbox_id,
            snapshot_id: state.snapshot_id.clone(),
            env_vars: state.env_vars.clone(),
            network: state.network.clone(),
            custom_extension_params: state.custom_extension_params.clone(),
            envd_access_token,
            ..Default::default()
        };
        let mut sandbox = ContainerSandbox::new(
            build_spec,
            launch,
            self.runtime.clone(),
            &self.paths,
            layers::LayerRefs::default(),
        );
        sandbox.restore = Some(Restore {
            criu_dir: state.criu_dir.clone(),
            tools: RestoreTools::Config(state.tools_image_config.clone()),
            rootfs_virtual_size: state.rootfs_virtual_size,
            envd_port: state.envd_port,
            archive: None,
        });
        sandbox.auth_mount = state.auth_mount;
        Ok(Box::new(sandbox))
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
    /// Set when this sandbox resumes a paused one instead of starting fresh.
    restore: Option<Restore>,
    /// Whether the container has the auth directory bound in: always for a
    /// new one, as dumped for a restored one.
    auth_mount: bool,
    /// A sandbox restored under an identity other than the dumped one (a
    /// full-fork child, or a launch from a snapshot): its restored envd
    /// holds the source's token until `/init` hands it this sandbox's own.
    new_identity: bool,
    /// The snapshot a launch restores, held until the sandbox stops: it
    /// keeps the cached artifacts the restore reads.
    snapshot_hold: Option<RunnableSnapshot>,
}

/// The exact tools image a restore needs.
#[derive(Clone, Debug)]
enum RestoreTools {
    /// Its image config on this node.
    Config(PathBuf),
    /// Its release, resolved when the sandbox starts.
    Release(String),
}

/// What resuming a paused container takes from its persisted state, beyond
/// the build spec: the dump and the exact tools image and sizes it ran with.
#[derive(Clone, Debug)]
struct Restore {
    criu_dir: PathBuf,
    /// The tools image the dumped processes map envd and busybox from.
    tools: RestoreTools,
    rootfs_virtual_size: Option<u64>,
    envd_port: u16,
    /// A tar of the CRIU images that start unpacks into `criu_dir`, which
    /// is removed once the sandbox is ready. Set for a launch from a
    /// snapshot.
    archive: Option<PathBuf>,
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
            restore: None,
            auth_mount: true,
            new_identity: false,
            snapshot_hold: None,
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
        // Snapshot publication stores a sealed layer without a descriptor
        // only under a runtime-generated delta's name; each sealed layer has
        // its own directory, so the name never collides.
        self.seal_layer(&device, &live_config, "snapshot.commit", "rootfs")
            .await
    }

    /// Restacks a writable device, whose filesystem the caller has frozen,
    /// onto a new sealed layer in its own directory under the sealed-layer
    /// base, which this sandbox references until its devices are gone.
    /// Returns the sealed stack's image config.
    async fn seal_layer(
        &mut self,
        device: &UblkDevice,
        live_config: &Path,
        layer_file: &str,
        kind: &'static str,
    ) -> SandboxCaptureResult<PathBuf> {
        let layer_dir = self
            .paths
            .layers_base
            .join(uuid::Uuid::now_v7().simple().to_string());
        let sealed = restack_snapshot_overlaybd_device(
            device,
            false,
            live_config,
            &layer_dir,
            layer_file,
            kind,
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

    /// Dumps the frozen processes into `root` and seals the rootfs and drives
    /// there, in that order and in one frozen window, so the files match the
    /// memory image. The processes stay frozen; the file systems are thawed.
    async fn capture_paused(&mut self, root: &Path) -> SandboxCaptureResult<ContainerPausedState> {
        let tools_image_config = self
            .tools
            .as_ref()
            .map(|tools| tools.image_config_path().to_path_buf())
            .context("container has no tools drive")
            .map_err(SandboxCaptureError::recoverable)?;
        let criu_dir = root.join("criu");
        self.runtime
            .checkpoint(&self.container_id, &criu_dir, &self.criu_work_dir())
            .await
            .context("dump container processes")
            .map_err(SandboxCaptureError::recoverable)?;
        super::failpoint::fail("container-pause-seal", None)
            .map_err(SandboxCaptureError::recoverable)?;

        let sealed = async {
            for mount in self.writable_drive_mounts() {
                sync_filesystem(&mount).map_err(SandboxCaptureError::recoverable)?;
                freeze(&mount).map_err(SandboxCaptureError::recoverable)?;
                self.frozen.push(mount);
            }
            let rootfs_mount = self.work_dir.join("rootfs");
            sync_filesystem(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
            freeze(&rootfs_mount).map_err(SandboxCaptureError::recoverable)?;
            self.frozen.push(rootfs_mount);
            let rootfs = self.seal_rootfs_into(&root.join("rootfs")).await?;
            let drives = self.seal_drives_into(&root.join("drives")).await?;
            Ok::<_, SandboxCaptureError>((rootfs, drives))
        }
        .await;
        let thawed = self.thaw_frozen();
        let (rootfs_image_config, extra_drives) = match sealed {
            Ok(sealed) => {
                thawed.map_err(SandboxCaptureError::terminal)?;
                sealed
            }
            Err(err) => return Err(capture_failure(err, thawed)),
        };

        Ok(ContainerPausedState {
            version: paused::STATE_VERSION,
            runtime: self.runtime.binary().to_owned(),
            criu_dir,
            rootfs_image_config,
            rootfs_virtual_size: self.rootfs_virtual_size,
            tools_image_config,
            extra_drives,
            resources: self.resources,
            context: self.build_spec.context.clone(),
            snapshot_id: self.launch.snapshot_id.clone(),
            env_vars: self.launch.env_vars.clone(),
            network: self.network_policy.clone(),
            custom_extension_params: self.custom_extension_params.clone(),
            envd_port: self.envd_port(ConfigManager::global_config()),
            auth_mount: self.auth_mount,
        })
    }

    /// The capture of a full fork: freeze the processes, dump them, and seal
    /// the writable volumes and the rootfs in the same frozen window, then
    /// let the processes run again. Volumes are sealed into their own
    /// directories, where the caller clones the children's volumes from.
    async fn capture_for_fork(&mut self) -> SandboxCaptureResult<fork::ContainerForkCapture> {
        let tools_image_config = self
            .tools
            .as_ref()
            .map(|tools| tools.image_config_path().to_path_buf())
            .context("container has no tools drive")
            .map_err(SandboxCaptureError::recoverable)?;
        let dir = fork::CaptureDir::create(&self.paths.captures_base)
            .map_err(SandboxCaptureError::recoverable)?;
        let (criu_dir, rootfs_image_config) = self
            .capture_frozen(dir.path(), "container-fork-seal", "a full fork")
            .await?;
        self.fork_capture(dir, criu_dir, rootfs_image_config, tools_image_config)
    }

    /// Freezes the processes, dumps them into `<dir>/criu` and seals the
    /// writable volumes and the rootfs in that frozen window, then lets the
    /// processes run again: memory, volumes and rootfs from one instant.
    /// Volumes are sealed into their own directories. Returns the dump and
    /// the sealed rootfs stack's image config.
    async fn capture_frozen(
        &mut self,
        dir: &Path,
        failpoint: &str,
        purpose: &str,
    ) -> SandboxCaptureResult<(PathBuf, PathBuf)> {
        self.refuse_writable_attached_drives()?;
        if self.has_exited() {
            return Err(SandboxCaptureError::terminal(anyhow!(
                "container sandbox {} has exited",
                self.id
            )));
        }
        let criu_dir = dir.join("criu");
        let started = std::time::Instant::now();
        self.runtime
            .pause(&self.container_id)
            .await
            .map_err(SandboxCaptureError::recoverable)?;
        let sealed = async {
            self.runtime
                .checkpoint(&self.container_id, &criu_dir, &self.criu_work_dir())
                .await
                .context("dump container processes")
                .map_err(SandboxCaptureError::recoverable)?;
            super::failpoint::fail(failpoint, None).map_err(SandboxCaptureError::recoverable)?;
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
        let resumed = self.thaw_paused().await;
        let rootfs_image_config = match sealed {
            Ok(image_config) => {
                resumed.map_err(SandboxCaptureError::terminal)?;
                image_config
            }
            // Dropping the caller's capture directory removes whatever the
            // dump wrote.
            Err(err) => return Err(capture_failure(err, resumed)),
        };
        info!(
            container = %self.container_id,
            capture = %dir.display(),
            elapsed = ?started.elapsed(),
            "container captured for {purpose}"
        );
        Ok((criu_dir, rootfs_image_config))
    }

    fn fork_capture(
        &self,
        dir: fork::CaptureDir,
        criu_dir: PathBuf,
        rootfs_image_config: PathBuf,
        tools_image_config: PathBuf,
    ) -> SandboxCaptureResult<fork::ContainerForkCapture> {
        let drives = self
            .drives
            .iter()
            .map(|attached| {
                Ok(fork::CapturedDrive {
                    drive: attached
                        .drive
                        .try_with_virtual_size(attached.runtime.actual_virtual_size)?,
                    per_child: attached.drive.is_volume(),
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(SandboxCaptureError::recoverable)?;
        Ok(fork::ContainerForkCapture {
            layers: std::sync::Mutex::new(self.layers.inherit()),
            dir,
            criu_dir,
            rootfs_image_config,
            rootfs_virtual_size: self.rootfs_virtual_size,
            tools_image_config,
            envd_port: self.envd_port(ConfigManager::global_config()),
            auth_mount: self.auth_mount,
            drives,
            build_spec: self.build_spec.clone(),
            snapshot_id: self.launch.snapshot_id.clone(),
            env_vars: self.launch.env_vars.clone(),
            network: self.network_policy.clone(),
            custom_extension_params: self.custom_extension_params.clone(),
            runtime: self.runtime.clone(),
            paths: self.paths.clone(),
        })
    }

    /// Describes a capture: the CRIU image archive, the sealed rootfs, the
    /// read-only attached drives as they are, and what a restore must
    /// rebuild. Volumes are left to the volume catalog, as for Firecracker.
    fn snapshot_manifest(
        &self,
        archive: &Path,
        rootfs_image_config: PathBuf,
    ) -> Result<crate::snapshot::SandboxSnapshotManifest> {
        let rootfs_virtual_size = self
            .rootfs_virtual_size
            .context("container rootfs size is unknown")?;
        let sized = self
            .drives
            .iter()
            .map(|attached| {
                attached
                    .drive
                    .try_with_virtual_size(attached.runtime.actual_virtual_size)
            })
            .collect::<Result<Vec<_>>>()?;
        let attached: Vec<_> = sized
            .iter()
            .filter(|drive| !drive.is_volume())
            .cloned()
            .collect();
        let section = crate::snapshot::ContainerSnapshotSection {
            runtime: self.runtime.binary().to_owned(),
            tools_version: snapshot::tools_version(&self.work_dir)?,
            envd_port: self.envd_port(ConfigManager::global_config()),
            auth_mount: self.auth_mount,
            resources: self.resources,
            mounts: snapshot::mounts_of(&sized),
        };
        crate::snapshot::SandboxSnapshotManifest::new(
            crate::snapshot::CONTAINER_BACKEND,
            archive,
            PathBuf::new(),
            0,
            rootfs_image_config,
            rootfs_virtual_size,
            &attached,
        )?
        .with_container(section)
    }

    /// Whether this sandbox can be captured for a fork or a snapshot,
    /// checked before anything is frozen; the error says why not. Nothing
    /// can share a writable attached drive, and `restored` (a fork child, a
    /// launch) takes a new access token from the source's envd only through
    /// the auth directory and the patched envd.
    fn check_capture(&self, restored: &str) -> Result<()> {
        if let Some(attached) = self.writable_attached_drive() {
            bail!(
                "it has writable attached drive '{}'",
                attached.drive.drive_id()
            );
        }
        if self.launch.envd_access_token.is_some() {
            if !self.auth_mount {
                bail!(
                    "it is secure and was started before {restored} could take its own access \
                     token; recreate it"
                );
            }
            if !self.tools_envd_has_patch(fork::ACCESS_TOKEN_PATCH) {
                bail!(
                    "it is secure, and its tools image's envd lacks the {} patch that hands \
                     {restored} its own access token (tools 0.1.2 or later)",
                    fork::ACCESS_TOKEN_PATCH
                );
            }
        }
        Ok(())
    }

    /// Forks cannot share a writable attached drive, and nothing gives each
    /// child its own copy.
    fn refuse_writable_attached_drives(&self) -> SandboxCaptureResult<()> {
        match self.writable_attached_drive() {
            Some(attached) => Err(SandboxCaptureError::recoverable(anyhow!(
                "cannot fork a container sandbox with writable attached drive '{}'",
                attached.drive.drive_id()
            ))),
            None => Ok(()),
        }
    }

    fn writable_attached_drive(&self) -> Option<&AttachedDrive> {
        self.drives
            .iter()
            .find(|attached| !attached.drive.read_only() && !attached.drive.is_volume())
    }

    /// Whether the mounted tools image lists `patch` among the patches its
    /// envd was built with (`/agentenv/envd-patches`).
    fn tools_envd_has_patch(&self, patch: &str) -> bool {
        std::fs::read_to_string(self.work_dir.join("tools/agentenv/envd-patches"))
            .is_ok_and(|patches| patches.lines().any(|line| line.trim() == patch))
    }

    fn has_exited(&self) -> bool {
        self.exited
            .as_ref()
            .is_some_and(|exited| exited.borrow().is_some())
    }

    /// Seals the rootfs, whose filesystem the caller has frozen, and stages
    /// the sealed stack into `output_dir`; returns the staged image config.
    async fn seal_rootfs_into(&mut self, output_dir: &Path) -> SandboxCaptureResult<PathBuf> {
        let sealed = self.restack_rootfs().await?;
        stage_into(&sealed, output_dir).await
    }

    /// Seals the drives, whose writable filesystems the caller has frozen,
    /// and returns them pointing at image configs that outlive this sandbox:
    /// - a volume: restacked in its own directory under a unique layer name,
    ///   as Firecracker's pause does;
    /// - a writable attached drive: sealed like the rootfs and staged under
    ///   `output_dir`;
    /// - a read-only drive: its own image config, which nothing has changed.
    async fn seal_drives_into(
        &mut self,
        output_dir: &Path,
    ) -> SandboxCaptureResult<Vec<ExtraDrive>> {
        let mut sealed = Vec::with_capacity(self.drives.len());
        for index in 0..self.drives.len() {
            let drive = self.drives[index].drive.clone();
            let device = self.drives[index].runtime.device.clone();
            let live_config = self.drives[index].runtime.image_config_path.clone();
            let virtual_size = self.drives[index].runtime.actual_virtual_size;
            let image_config = if let Some(volume_dir) = drive.snapshot_output_dir() {
                let layer = format!("snapshot-{}.commit", uuid::Uuid::now_v7().simple());
                Some(
                    restack_snapshot_overlaybd_device(
                        &device,
                        drive.read_only(),
                        &live_config,
                        volume_dir,
                        &layer,
                        "volume",
                    )
                    .await
                    .map_err(SandboxCaptureError::from),
                )
            } else if drive.read_only() {
                None
            } else {
                let sealed = self
                    .seal_layer(&device, &live_config, "drive.commit", "drive")
                    .await;
                Some(match sealed {
                    Ok(sealed) => stage_into(&sealed, &output_dir.join(drive.drive_id())).await,
                    Err(err) => Err(err),
                })
            };
            let drive = match image_config {
                Some(Ok(image_config)) => drive.with_image_config_path(image_config),
                Some(Err(err)) => {
                    return Err(match err {
                        SandboxCaptureError::Terminal(err) => SandboxCaptureError::terminal(
                            err.context(format!("seal drive '{}'", drive.drive_id())),
                        ),
                        SandboxCaptureError::Recoverable(err) => SandboxCaptureError::recoverable(
                            err.context(format!("seal drive '{}'", drive.drive_id())),
                        ),
                    })
                }
                None => drive,
            };
            sealed.push(
                drive
                    .try_with_virtual_size(virtual_size)
                    .map_err(SandboxCaptureError::recoverable)?,
            );
        }
        Ok(sealed)
    }

    /// Host mounts of the drives the sandbox can write.
    fn writable_drive_mounts(&self) -> Vec<PathBuf> {
        self.drives
            .iter()
            .filter(|attached| !attached.drive.read_only())
            .filter_map(|attached| attached.host_mount.clone())
            .collect()
    }

    /// Thaws file systems and processes a pause left frozen.
    async fn thaw_paused(&mut self) -> Result<()> {
        let thawed = self.thaw_frozen();
        let resumed = self.runtime.resume(&self.container_id).await;
        thawed.and(resumed)
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
        let tools_config = match self.restore.as_ref().map(|restore| &restore.tools) {
            // The restored processes map envd and busybox from this image.
            Some(RestoreTools::Config(path)) => path.clone(),
            Some(RestoreTools::Release(version)) => resolve_tools_image(config, version)
                .await?
                .with_context(|| format!("tools image {version} is not an OverlayBD image"))?,
            None => resolve_tools_image(config, config.resolved_tools_version())
                .await?
                .context("the container backend needs an OverlayBD tools image")?,
        };
        let tools = UblkDeviceManager::global()
            .get_or_create_shared_tools(&UblkCreateSpec::Overlaybd {
                image_config: tools_config,
                global_config: global_config.clone(),
            })
            .await
            .context("attach tools drive")?;
        let tools_device = tools.device_path().to_path_buf();
        self.tools = Some(tools);

        let requested_virtual_size = match (&self.restore, self.resources.disk_size_mib) {
            // A resumed filesystem keeps the size it was paused with.
            (Some(restore), _) => restore.rootfs_virtual_size,
            (None, 0) => None,
            (None, mib) => Some(
                u64::from(mib)
                    .checked_mul(1024 * 1024)
                    .context("requested rootfs size overflows bytes")?,
            ),
        };
        let known_source_virtual_size = self
            .restore
            .as_ref()
            .and_then(|restore| restore.rootfs_virtual_size);
        let rootfs = UblkDeviceManager::global()
            .create_overlaybd_runtime_device(CreateOverlaybdRuntimeDeviceRequest {
                source_image_config: &self.build_spec.image_config_path,
                global_config: &global_config,
                runtime_dir: &self.work_dir.join("overlaybd"),
                read_only: false,
                runtime_upper_mode: config.ublk.overlaybd.runtime_upper_mode,
                requested_virtual_size,
                known_source_virtual_size,
                allow_shrink: self.restore.is_none() && config.ublk.overlaybd.allow_shrink,
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
        let mode = match self.restore {
            // Sealed drives carry the sizes they were paused with.
            Some(_) => ExtraDrivePrepareMode::Resume,
            None => ExtraDrivePrepareMode::Fresh {
                allow_shrink: config.ublk.overlaybd.allow_shrink,
            },
        };
        let (attachments, runtimes) = prepare_extra_drives(
            &drives,
            global_config,
            &self.work_dir,
            config.ublk.overlaybd.runtime_upper_mode,
            |_| mode,
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
        let mut child = match &self.restore {
            Some(restore) => {
                super::failpoint::fail("container-restore", None)?;
                self.runtime.restore(
                    &self.work_dir,
                    &self.container_id,
                    &restore.criu_dir,
                    &self.criu_work_dir(),
                )?
            }
            None => self.runtime.run(&self.work_dir, &self.container_id)?,
        };
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

    /// CRIU's work directory: its logs for a dump or restore.
    fn criu_work_dir(&self) -> PathBuf {
        self.work_dir.join("criu")
    }

    /// envd's port: the one a restored envd already listens on, or the
    /// node's.
    fn envd_port(&self, config: &AppConfig) -> u16 {
        self.restore
            .as_ref()
            .map_or(config.tools.control_plane_port, |restore| restore.envd_port)
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
            envd_port: self.envd_port(config),
            cgroups_path: &cgroups_path,
            drives: &self.drive_binds(),
            restore: self.restore.is_some(),
            auth: self.auth_mount,
        })?;
        if self.new_identity {
            self.hand_over_access_token()?;
        }
        if let Some(Restore {
            criu_dir,
            archive: Some(archive),
            ..
        }) = &self.restore
        {
            snapshot::unpack(archive.clone(), criu_dir.clone()).await?;
        }
        self.start_runtime()?;

        let host_ip = self.host_interaction_ip().context("network slot missing")?;
        self.envd = Some(EnvdInstance::new(
            format!("http://{host_ip}:{}", self.envd_port(config)),
            self.launch.envd_access_token.clone(),
        ));
        info!(
            container = %self.container_id,
            work_dir = %self.work_dir.display(),
            restored = self.restore.is_some(),
            "container started"
        );
        Ok(())
    }

    /// Names this sandbox's own access token, or none, in its auth
    /// directory, which its restored envd checks when `/init` brings a token
    /// other than the source's it holds. A source without the auth directory
    /// was not secure (captures of secure ones are refused): its envd holds
    /// no token and takes the first one `/init` brings.
    fn hand_over_access_token(&self) -> Result<()> {
        if !self.auth_mount {
            return Ok(());
        }
        let token = self
            .launch
            .envd_access_token
            .as_ref()
            .map_or("", EnvdAccessToken::expose);
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha512::digest(token.as_bytes()));
        std::fs::write(
            self.work_dir
                .join(bundle::AUTH_DIR)
                .join(bundle::ACCESS_TOKEN_HASH),
            hash,
        )
        .context("write the access token hash for a restored envd")
    }

    /// Waits until the runtime reports a restored container running. CRIU
    /// drops the container's packets until the restore is complete, so an
    /// earlier envd probe would only time out.
    /// The caller bounds the whole wait.
    async fn wait_restored(&self) -> Result<()> {
        loop {
            if self.runtime.status(&self.container_id).await?.as_deref() == Some("running") {
                return Ok(());
            }
            tokio::time::sleep(RESTORE_POLL).await;
        }
    }

    async fn ready_inner(&self) -> Result<()> {
        let config = ConfigManager::global_config();
        let envd = self.envd.as_ref().context("container has not started")?;
        let mut exited = self.exited.clone().context("container has not started")?;
        let timeout = Duration::from_secs(config.envd.init_timeout_secs);
        let started = std::time::Instant::now();
        // One deadline covers waiting for the restore and for envd.
        let ready = tokio::time::timeout(timeout, async {
            let poll = Duration::from_millis(config.envd.poll_ms);
            if self.restore.is_none() {
                return envd.wait_for_ready(timeout, poll).await;
            }
            self.wait_restored().await?;
            debug!(container = %self.container_id, elapsed = ?started.elapsed(), "container restored");
            // The runtime reports the container running just before CRIU
            // stops dropping its packets: retry dropped probes quickly.
            let remaining = timeout.saturating_sub(started.elapsed());
            envd.wait_for_ready_probing(remaining, poll, RESTORE_FIRST_PROBE)
                .await
        });
        tokio::select! {
            result = ready => result.map_err(|_| {
                anyhow!("container was not ready within {}s", timeout.as_secs())
            })??,
            changed = exited.wait_for(Option::is_some) => {
                let exit = changed
                    .map(|exit| exit.clone().unwrap_or_default())
                    .unwrap_or_else(|_| "unknown".to_owned());
                let criu = match self.restore {
                    Some(_) => runtime::criu_errors(&self.criu_work_dir().join("restore.log")),
                    None => String::new(),
                };
                if !criu.is_empty() {
                    bail!("container restore failed ({exit}): criu: {criu}");
                }
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
        debug!(container = %self.container_id, elapsed = ?started.elapsed(), "envd answers");
        let init = envd
            .init(
                (!env_vars.is_empty()).then_some(env_vars),
                Some(context.workdir.clone()),
                context.user.clone(),
            )
            .await;
        if self.new_identity {
            const NEEDS_PATCH: &str = "envd must be built with the tools image's \
                                       access-token-hash-file patch";
            init.with_context(|| {
                format!("initialize the restored envd with this sandbox's token ({NEEDS_PATCH})")
            })?;
            // `/init` can answer 204 without switching; only routing the
            // sandbox once its own token works keeps the source's out of it.
            envd.verify_access_token().await.with_context(|| {
                format!("hand the restored envd this sandbox's token ({NEEDS_PATCH})")
            })?;
        } else {
            init.context("initialize envd")?;
        }
        if let Some(Restore {
            criu_dir,
            archive: Some(_),
            ..
        }) = &self.restore
        {
            // The processes are restored; the unpacked images are not needed.
            if let Err(err) = std::fs::remove_dir_all(criu_dir) {
                warn!(dump = %criu_dir.display(), error = %err, "failed to remove unpacked CRIU images");
            }
        }
        debug!(container = %self.container_id, elapsed = ?started.elapsed(), "envd initialized");
        Ok(())
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
        if self.rootfs.is_none() && self.drives.is_empty() {
            // Nothing of this sandbox stacks on its sealed layers any more: a
            // writable attached drive kept for the next attempt may, once
            // sealed, stack on one of them too.
            self.layers.release();
        }
        if failures.is_empty() {
            self.snapshot_hold = None;
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

    /// Persistent pause: freeze the processes, dump them and seal the file
    /// systems into `artifact_root`. The processes stay frozen until `stop`
    /// releases everything, or until `resume` thaws them if the pause is not
    /// kept. Any failure thaws them again.
    async fn pause(
        &mut self,
        artifact_root: Option<&Path>,
    ) -> SandboxCaptureResult<Arc<dyn PausedSandboxState>> {
        let root = artifact_root
            .context("pausing a container sandbox needs an artifact root")
            .map_err(SandboxCaptureError::recoverable)?;
        if self.has_exited() {
            // Nothing is left to keep running: the sandbox must be cleaned up,
            // not put back.
            return Err(SandboxCaptureError::terminal(anyhow!(
                "container sandbox {} has exited",
                self.id
            )));
        }
        self.runtime
            .pause(&self.container_id)
            .await
            .map_err(SandboxCaptureError::recoverable)?;
        match self.capture_paused(root).await {
            Ok(state) => {
                info!(container = %self.container_id, root = %root.display(), "container paused");
                Ok(Arc::new(state))
            }
            Err(err) => {
                // The live devices stack only on sealed layers this sandbox
                // references, never on the artifact root: drop what the
                // failed pause wrote there.
                for dir in ["criu", "rootfs", "drives"] {
                    let _ = std::fs::remove_dir_all(root.join(dir));
                }
                let resumed = self.thaw_paused().await;
                Err(capture_failure(err, resumed))
            }
        }
    }

    /// Thaws a paused container that has not been stopped yet.
    async fn resume(&mut self) -> Result<()> {
        self.thaw_paused().await
    }

    /// A memory snapshot: captured in one frozen window like a full fork,
    /// with the CRIU images packed into one archive afterwards, while the
    /// sandbox already runs again. The capture holds the archive and the
    /// sealed rootfs layers until the snapshot is published.
    async fn snapshot(&mut self) -> SandboxCaptureResult<CapturedSandboxSnapshot> {
        self.check_capture("a sandbox launched from it")
            .context("cannot snapshot this sandbox")
            .map_err(SandboxCaptureError::recoverable)?;
        let dir = fork::CaptureDir::create(&self.paths.captures_base)
            .map_err(SandboxCaptureError::recoverable)?;
        let (criu_dir, rootfs_image_config) = self
            .capture_frozen(dir.path(), "container-snapshot-seal", "a snapshot")
            .await?;
        let hold = layers::LayerHold::new(self.layers.inherit());
        let archive = dir.path().join("criu.tar");
        let manifest = async {
            snapshot::pack(criu_dir.clone(), archive.clone()).await?;
            std::fs::remove_dir_all(&criu_dir)
                .with_context(|| format!("remove {}", criu_dir.display()))?;
            self.snapshot_manifest(&archive, rootfs_image_config)
        }
        .await
        .map_err(SandboxCaptureError::recoverable)?;
        Ok(CapturedSandboxSnapshot::new(manifest, (dir, hold)))
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
        self.refuse_writable_attached_drives()?;
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
                    let err = err.context("start forked container");
                    match child.stop().await {
                        Ok(()) => Err(err),
                        Err(stop_err) => {
                            warn!(error = %format_args!("{stop_err:#}"), "failed to stop fork child after start failure");
                            Err(UnstoppedForkChild::error(err, Some(Box::new(child)), &stop_err))
                        }
                    }
                }
            }
        }))
        .await;
        Ok(started)
    }

    fn check_fork(&self, mode: crate::types::SandboxForkMode) -> Result<()> {
        match mode {
            crate::types::SandboxForkMode::Full => self.check_capture("a fork child"),
            crate::types::SandboxForkMode::Filesystem => match self.writable_attached_drive() {
                Some(attached) => bail!(
                    "it has writable attached drive '{}'",
                    attached.drive.drive_id()
                ),
                None => Ok(()),
            },
        }
    }

    fn check_snapshot(&self) -> Result<()> {
        self.check_capture("a sandbox launched from it")
    }

    async fn capture_fork(&mut self) -> SandboxCaptureResult<Box<dyn SandboxForkCapture>> {
        self.pending_fork_rootfs = None;
        Ok(Box::new(self.capture_for_fork().await?))
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

    #[test]
    fn only_criu_runtimes_can_pause() {
        assert!(runtime_checkpoints_with_criu("runc"));
        assert!(runtime_checkpoints_with_criu("/usr/sbin/crun"));
        assert!(!runtime_checkpoints_with_criu("runsc"));
        assert!(!runtime_checkpoints_with_criu("/usr/local/bin/runsc"));
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
                captures_base: temp.path().join("missing-captures"),
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
                captures_base: temp.path().join("captures"),
            },
        };
        std::fs::create_dir_all(temp.path().join("layers/old"))?;
        std::fs::create_dir_all(temp.path().join("captures/old/criu"))?;
        factory.reconcile().await?;
        assert!(!leftover.exists());
        assert!(!temp.path().join("layers").exists());
        assert!(!temp.path().join("captures").exists());
        Ok(())
    }
}
