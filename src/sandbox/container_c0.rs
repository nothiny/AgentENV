//! C0 spike for the container backend.
//!
//! Proves that one sandbox can run as an OCI container whose rootfs is the
//! same OverlayBD/ublk device Firecracker would use, inside a slot-shaped
//! netns where a veth pair takes the place of `tap0`, with the tools-drive
//! envd as the guest agent. Every phase is timed.
//!
//! Run as root inside the privileged dev container:
//!
//! ```text
//! AENV_CONFIG_PATH=/src/scripts/tests/container-backend-c0/c0.toml \
//! C0_IMAGE=docker.io/library/ubuntu:22.04 \
//! cargo test -p agentenv --lib container_c0 -- --ignored --nocapture
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use uvm_ublk_daemon::CreateOverlaybdRuntimeDeviceRequest;

use super::envd::EnvdInstance;
use super::process::Executor;
use super::ublk::{SharedReadOnlyDevice, UblkCreateSpec, UblkDevice};
use super::{resolve_tools_image, SandboxAccessTokenGenerator, UblkDeviceManager};
use crate::cfg::ConfigManager;
use crate::image::ImageResolver;
use crate::types::SandboxId;

const SLOT_NS: &str = "yzc0-slot";
const CTR_NS: &str = "yzc0-ctr";
const HOST_VETH: &str = "yzc0h";
const HOST_VETH_IP: &str = "10.231.0.1";
const VPEER_IP: &str = "10.231.0.2";
const HOST_INTERACTION_IP: &str = "10.232.0.2";
const TAP_IP: &str = "169.254.0.21";
const VM_IP: &str = "169.254.0.22";
const ENVD_PORT: u16 = 49983;

const CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

const INIT_SCRIPT: &str = r#"#!/agentenv/bin/busybox sh
# Container-mode counterpart of the tools drive's pivot-init: no pivot_root,
# no kernel ip= arguments, no runsv; envd runs as PID 1.
BB=/agentenv/bin/busybox
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
$BB mkdir -p /usr/local/bin /usr/bin /bin /run/lock /tmp /var/log/agentenv/envd
$BB ln -sf /agentenv/envd /usr/local/bin/envd
[ -x /usr/bin/nice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/nice
[ -x /usr/bin/ionice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/ionice
[ -x /bin/sh ] || $BB ln -sf /agentenv/bin/busybox /bin/sh
[ -e /etc/passwd ] || $BB printf 'root:x:0:0:root:/root:/bin/sh\n' > /etc/passwd
exec /agentenv/envd -isnotfc
"#;

struct Timings(Vec<(&'static str, Duration)>);

impl Timings {
    fn record(&mut self, name: &'static str, start: Instant) {
        self.0.push((name, start.elapsed()));
    }
    fn print(&self) {
        println!("\n== C0 timings ==");
        for (name, d) in &self.0 {
            println!("{name:<28} {:>9.1} ms", d.as_secs_f64() * 1e3);
        }
    }
}

fn sh(args: &[&str]) -> Result<String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {args:?}"))?;
    if !out.status.success() {
        bail!(
            "{args:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Best-effort cleanup command; prints failures but never stops cleanup.
fn try_sh(args: &[&str]) {
    if let Err(err) = sh(args) {
        println!("cleanup: {err:#}");
    }
}

fn in_ns(ns: &str, args: &[&str]) -> Result<String> {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sh(&full)
}

/// Mirror of `Slot`: host veth <-> vpeer in a slot netns, with the same
/// FORWARD/SNAT/DNAT rules, except the guest side is a veth into a separate
/// container netns instead of `tap0`.
fn setup_network(guest_if_in_slot: &str) -> Result<()> {
    sh(&["ip", "netns", "add", SLOT_NS])?;
    sh(&["ip", "netns", "add", CTR_NS])?;
    sh(&[
        "ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", "vpeer", "netns", SLOT_NS,
    ])?;
    sh(&[
        "ip",
        "addr",
        "add",
        &format!("{HOST_VETH_IP}/30"),
        "dev",
        HOST_VETH,
    ])?;
    sh(&["ip", "link", "set", HOST_VETH, "up"])?;
    sh(&[
        "ip",
        "route",
        "add",
        &format!("{HOST_INTERACTION_IP}/32"),
        "via",
        VPEER_IP,
    ])?;

    in_ns(SLOT_NS, &["ip", "link", "set", "lo", "up"])?;
    in_ns(
        SLOT_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{VPEER_IP}/30"),
            "dev",
            "vpeer",
        ],
    )?;
    in_ns(SLOT_NS, &["ip", "link", "set", "vpeer", "up"])?;
    in_ns(
        SLOT_NS,
        &["ip", "route", "add", "default", "via", HOST_VETH_IP],
    )?;
    in_ns(SLOT_NS, &["sysctl", "-qw", "net.ipv4.ip_forward=1"])?;

    // The tap0 replacement: one end stays in the slot netns, the other end
    // becomes the container's eth0.
    in_ns(
        SLOT_NS,
        &[
            "ip",
            "link",
            "add",
            guest_if_in_slot,
            "type",
            "veth",
            "peer",
            "name",
            "ctr0",
            "netns",
            CTR_NS,
        ],
    )?;
    in_ns(
        SLOT_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{TAP_IP}/30"),
            "dev",
            guest_if_in_slot,
        ],
    )?;
    in_ns(SLOT_NS, &["ip", "link", "set", guest_if_in_slot, "up"])?;
    in_ns(CTR_NS, &["ip", "link", "set", "lo", "up"])?;
    in_ns(CTR_NS, &["ip", "link", "set", "ctr0", "name", "eth0"])?;
    in_ns(
        CTR_NS,
        &["ip", "addr", "add", &format!("{VM_IP}/30"), "dev", "eth0"],
    )?;
    in_ns(CTR_NS, &["ip", "link", "set", "eth0", "up"])?;
    in_ns(CTR_NS, &["ip", "route", "add", "default", "via", TAP_IP])?;

    // Same rule set as Slot::configure_namespace_iptables_rules, with the
    // interface name parameterized.
    let g = guest_if_in_slot;
    for rule in [
        vec!["-A", "FORWARD", "-i", g, "-o", "vpeer", "-j", "ACCEPT"],
        vec![
            "-A",
            "FORWARD",
            "-i",
            "vpeer",
            "-o",
            g,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "vpeer",
            "-s",
            VM_IP,
            "-j",
            "SNAT",
            "--to",
            HOST_INTERACTION_IP,
        ],
        vec![
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            "vpeer",
            "-d",
            HOST_INTERACTION_IP,
            "-j",
            "DNAT",
            "--to",
            VM_IP,
        ],
        vec![
            "-t",
            "raw",
            "-A",
            "PREROUTING",
            "-i",
            g,
            "!",
            "-s",
            VM_IP,
            "-j",
            "DROP",
        ],
    ] {
        let mut args = vec!["iptables"];
        args.extend(rule);
        in_ns(SLOT_NS, &args)?;
    }

    // The dev container's own netns plays the node host: forward and
    // masquerade slot traffic out of its eth0.
    sh(&["sysctl", "-qw", "net.ipv4.ip_forward=1"])?;
    sh(&[
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        &format!("{HOST_INTERACTION_IP}/32"),
        "-o",
        "eth0",
        "-j",
        "MASQUERADE",
    ])?;
    Ok(())
}

fn teardown_network() {
    try_sh(&[
        "iptables",
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        &format!("{HOST_INTERACTION_IP}/32"),
        "-o",
        "eth0",
        "-j",
        "MASQUERADE",
    ]);
    try_sh(&["ip", "route", "del", &format!("{HOST_INTERACTION_IP}/32")]);
    try_sh(&["ip", "link", "del", HOST_VETH]);
    try_sh(&["ip", "netns", "del", CTR_NS]);
    try_sh(&["ip", "netns", "del", SLOT_NS]);
}

fn host_nameservers() -> String {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("nameserver") && !l.contains("127."))
        .map(|l| format!("{l}\n"))
        .collect()
}

fn bind(dest: &str, source: &Path, ro: bool) -> Value {
    let mut options = vec!["rbind", "nosuid", "nodev"];
    if ro {
        options.push("ro");
    }
    json!({"destination": dest, "type": "bind", "source": source, "options": options})
}

fn oci_config(work: &Path, hostname: &str, ctr_id: &str) -> Value {
    let caps: Vec<&str> = CAPS.to_vec();
    json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/agentenv/bin/busybox", "sh", "/.aenv-init"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"],
            "cwd": "/",
            "capabilities": {"bounding": caps, "effective": caps, "permitted": caps},
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1048576u64, "soft": 1048576u64}],
            "noNewPrivileges": true
        },
        "root": {"path": work.join("rootfs"), "readonly": false},
        "hostname": hostname,
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
            {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]},
            {"destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=755"]},
            bind("/agentenv", &work.join("tools/agentenv"), true),
            bind("/.aenv-init", &work.join("init.sh"), true),
            bind("/etc/resolv.conf", &work.join("etc/resolv.conf"), true),
            bind("/etc/hosts", &work.join("etc/hosts"), true),
            bind("/etc/hostname", &work.join("etc/hostname"), true)
        ],
        "linux": {
            "cgroupsPath": format!("/aenv-ct/{ctr_id}"),
            "resources": {
                "memory": {"limit": 2147483648u64, "swap": 2147483648u64},
                "cpu": {"quota": 200000, "period": 100000},
                "pids": {"limit": 4096}
            },
            "namespaces": [
                {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, {"type": "cgroup"},
                {"type": "network", "path": format!("/run/netns/{CTR_NS}")}
            ],
            "maskedPaths": ["/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi"],
            "readonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
        }
    })
}

struct Devices {
    tools: Option<SharedReadOnlyDevice>,
    rootfs: Option<UblkDevice>,
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "C0 spike: needs root, ublk, runc and network namespaces"]
async fn container_c0() -> Result<()> {
    crate::logging::init_for_tests();
    let image =
        std::env::var("C0_IMAGE").unwrap_or_else(|_| "docker.io/library/ubuntu:22.04".into());
    let runtime = std::env::var("C0_RUNTIME").unwrap_or_else(|_| "runc".into());
    let config = ConfigManager::init_global()?.config();
    let sandbox_id = SandboxId::new();
    let ctr_id = format!("yzc0-{sandbox_id}");
    let work = PathBuf::from(format!("/state/c0/{sandbox_id}"));
    let runc_root = "/run/yzd-aenv-ct/runc";
    fs::create_dir_all(work.join("rootfs"))?;
    fs::create_dir_all(work.join("tools"))?;
    fs::create_dir_all(work.join("etc"))?;
    fs::create_dir_all(runc_root)?;
    println!(
        "sandbox={sandbox_id} image={image} runtime={runtime} work={}",
        work.display()
    );

    let mut t = Timings(Vec::new());
    let mut devices = Devices {
        tools: None,
        rootfs: None,
    };
    let mut mounted: Vec<PathBuf> = Vec::new();
    let mut network_up = false;
    let mut container_created = false;

    let result: Result<()> = async {
        let s = Instant::now();
        UblkDeviceManager::init_global_from_config(config).await?;
        t.record("ublk daemon init", s);

        // Image -> OverlayBD config (cached after the first run).
        let s = Instant::now();
        let resolved = ImageResolver::new(config)
            .resolve(&image)
            .await
            .map_err(|e| anyhow!("resolve {image}: {e:?}"))?;
        t.record("image resolve", s);
        let tools_cfg = resolve_tools_image(config, config.resolved_tools_version())
            .await?
            .context("tools image config missing")?;

        // Devices: identical to what Firecracker would attach as vda/vdb.
        let global = config.ublk.overlaybd.global_config_path.clone();
        let s = Instant::now();
        let tools = UblkDeviceManager::global()
            .get_or_create_shared_tools(&UblkCreateSpec::Overlaybd { image_config: tools_cfg, global_config: global.clone() })
            .await?;
        let tools_dev = tools.device_path().to_path_buf();
        devices.tools = Some(tools);
        t.record("tools device", s);

        let s = Instant::now();
        let rootfs = UblkDeviceManager::global()
            .create_overlaybd_runtime_device(CreateOverlaybdRuntimeDeviceRequest {
                source_image_config: &resolved.overlaybd_config_path,
                global_config: &global,
                runtime_dir: &work.join("overlaybd"),
                read_only: false,
                runtime_upper_mode: config.ublk.overlaybd.runtime_upper_mode,
                requested_virtual_size: None,
                known_source_virtual_size: None,
                allow_shrink: false,
            })
            .await?;
        let rootfs_dev = rootfs.device.device_path().to_path_buf();
        println!("rootfs={} ({} MiB) tools={}", rootfs_dev.display(), rootfs.actual_virtual_size >> 20, tools_dev.display());
        devices.rootfs = Some(rootfs.device);
        t.record("rootfs device", s);

        // Host-side mounts.
        let s = Instant::now();
        let rootfs_dir = work.join("rootfs");
        sh(&["mount", "-t", "ext4", "-o", "noatime", rootfs_dev.to_str().unwrap(), rootfs_dir.to_str().unwrap()])?;
        mounted.push(rootfs_dir);
        let tools_dir = work.join("tools");
        sh(&["mount", "-t", "ext4", "-o", "ro,noatime", tools_dev.to_str().unwrap(), tools_dir.to_str().unwrap()])?;
        mounted.push(tools_dir);
        t.record("mount rootfs+tools", s);

        // Bundle.
        let hostname = "c0";
        fs::write(work.join("init.sh"), INIT_SCRIPT)?;
        fs::write(work.join("etc/resolv.conf"), host_nameservers())?;
        fs::write(work.join("etc/hosts"), format!("127.0.0.1 localhost\n::1 localhost\n{VM_IP} {hostname}\n"))?;
        fs::write(work.join("etc/hostname"), format!("{hostname}\n"))?;
        fs::write(work.join("config.json"), serde_json::to_vec_pretty(&oci_config(&work, hostname, &ctr_id))?)?;

        let s = Instant::now();
        setup_network("ctr0h")?;
        network_up = true;
        t.record("network (slot+veth)", s);

        // runc create + start; stdio goes to a log file (pass-through mode).
        let log = fs::File::create(work.join("console.log"))?;
        let s = Instant::now();
        let status = Command::new(&runtime)
            .args(["--root", runc_root, "create", "--bundle", work.to_str().unwrap(), "--pid-file", work.join("pid").to_str().unwrap(), &ctr_id])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .status()?;
        ensure!(status.success(), "{runtime} create failed: {}", fs::read_to_string(work.join("console.log")).unwrap_or_default());
        container_created = true;
        t.record("runtime create", s);
        let s = Instant::now();
        sh(&[&runtime, "--root", runc_root, "start", &ctr_id])?;
        t.record("runtime start", s);

        // envd: health, init, exec, files.
        let token = SandboxAccessTokenGenerator::new("c0-spike-seed")?.generate(sandbox_id);
        let endpoint = format!("http://{HOST_INTERACTION_IP}:{ENVD_PORT}");
        let envd = EnvdInstance::new(endpoint.clone(), Some(token.clone()));
        let s = Instant::now();
        envd.wait_for_ready(Duration::from_secs(10), Duration::from_millis(5)).await?;
        t.record("envd health", s);
        let host_time_before = chrono::Utc::now();
        let s = Instant::now();
        let mut env = resolved.base_context.env_vars.clone();
        env.insert("C0_MARKER".into(), "from-init".into());
        let init = envd.init(Some(env), resolved.base_context.workdir.clone(), resolved.base_context.user.clone()).await;
        t.record("envd init", s);
        if let Err(err) = &init {
            println!("envd init error: {err:#}");
        }
        init?;

        let exec = Executor::for_endpoint(endpoint.clone(), Some(token.clone()));
        let s = Instant::now();
        let out = exec.run_command("true", &[]).await?;
        t.record("first exec (true)", s);
        ensure!(out.exit_code == 0, "true exited {}", out.exit_code);

        for (label, script) in [
            ("os", "head -2 /etc/os-release; uname -r; hostname; id"),
            ("env", "echo C0_MARKER=$C0_MARKER PATH=$PATH; pwd"),
            ("files", "echo hello > /tmp/c0-file && cat /tmp/c0-file && ls -la /agentenv | head -5"),
            ("limits", "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max"),
            ("procs", "ps -eo pid,ppid,comm 2>/dev/null || /agentenv/bin/busybox ps"),
            ("rootfs", "df -h / | tail -1; mount | grep ' / '"),
            ("net", "ip -br addr 2>/dev/null || /agentenv/bin/busybox ip addr; /agentenv/bin/busybox wget -q -T 5 -O- http://example.com 2>&1 | head -c 80; echo; echo wget_exit=$?"),
            ("caps", "grep Cap /proc/self/status"),
        ] {
            let out = exec.run_command("sh", &["-c", script]).await?;
            println!("--- {label} (exit {})\n{}{}", out.exit_code, out.stdout, out.stderr);
        }

        // A wrong token must be rejected.
        let wrong = SandboxAccessTokenGenerator::new("another-seed")?.generate(sandbox_id);
        let rejected = Executor::for_endpoint(endpoint.clone(), Some(wrong)).run_command("true", &[]).await;
        println!("--- wrong token rejected: {}", rejected.is_err());
        ensure!(rejected.is_err(), "envd accepted a wrong token");

        // envd init sends a timestamp; make sure the node clock was not moved.
        let skew = (chrono::Utc::now() - host_time_before).num_milliseconds();
        println!("--- host clock advanced {skew} ms across init+exec (expect small, non-negative)");

        let rss = fs::read_to_string(format!("/sys/fs/cgroup/aenv-ct/{ctr_id}/memory.current")).unwrap_or_default();
        if !rss.trim().is_empty() {
            println!("--- container memory.current = {} KiB", rss.trim().parse::<u64>().unwrap_or(0) / 1024);
        }
        Ok(())
    }
    .await;

    // Cleanup in reverse order, always.
    let s = Instant::now();
    if container_created {
        try_sh(&[&runtime, "--root", runc_root, "kill", &ctr_id, "KILL"]);
        std::thread::sleep(Duration::from_millis(200));
        try_sh(&[&runtime, "--root", runc_root, "delete", "--force", &ctr_id]);
    }
    if network_up {
        teardown_network();
    }
    for dir in mounted.iter().rev() {
        try_sh(&["umount", dir.to_str().unwrap()]);
    }
    if let Some(dev) = devices.rootfs.take() {
        if let Err(err) = UblkDeviceManager::global().delete_device(&dev).await {
            println!("cleanup: delete rootfs device: {err:#}");
        }
    }
    if let Some(tools) = devices.tools.take() {
        if let Err(err) = tools.release().await {
            println!("cleanup: release tools device: {err:#}");
        }
    }
    t.record("cleanup", s);
    if let Err(err) = UblkDeviceManager::global().shutdown_daemon().await {
        println!("cleanup: shutdown ublk daemon: {err:#}");
    }
    t.print();
    if let Ok(log) = fs::read_to_string(work.join("console.log")) {
        println!("\n== container console (last 30 lines) ==");
        for line in log
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            println!("{line}");
        }
    }
    result
}
