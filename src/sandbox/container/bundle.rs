//! OCI bundle for a container sandbox: `config.json` plus the files it binds
//! into the container.
//!
//! Layout under the sandbox work directory:
//!
//! ```text
//! rootfs/            the OverlayBD rootfs device, mounted read-write
//! tools/             the tools drive, mounted read-only; tools/agentenv -> /agentenv
//! init.sh            one-time guest setup, bound at /.aenv-init
//! inittab            busybox init's table, bound at /etc/inittab
//! etc/{resolv.conf,hosts,hostname}
//! netns              the container's network namespace
//! config.json
//! ```

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::types::SandboxResources;

/// Container counterpart of the tools drive's `pivot-init`, run once by
/// busybox init before envd: no pivot_root and no kernel `ip=` arguments, as
/// the bundle provides rootfs, mounts, network and /etc files.
pub(super) const INIT_SCRIPT: &str = r#"#!/agentenv/bin/busybox sh
BB=/agentenv/bin/busybox
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
$BB mkdir -p /usr/local/bin /usr/bin /bin /run/lock /tmp /var/log/agentenv/envd
$BB ln -sf /agentenv/envd /usr/local/bin/envd
[ -x /usr/bin/nice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/nice
[ -x /usr/bin/ionice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/ionice
[ -x /bin/sh ] || $BB ln -sf /agentenv/bin/busybox /bin/sh
if [ ! -e /etc/passwd ]; then
    shell=/bin/sh
    [ -x /bin/bash ] && shell=/bin/bash
    $BB mkdir -p /etc /root
    $BB printf 'root:x:0:0:root:/root:%s\n' "$shell" > /etc/passwd
fi
"#;

/// busybox init is PID 1: it reaps orphaned processes, which envd does not,
/// and restarts envd if it dies, as runsv does in the VM.
fn inittab(envd_port: u16) -> String {
    format!(
        "::sysinit:/agentenv/bin/busybox sh /.aenv-init\n\
         ::respawn:/agentenv/envd -isnotfc -port {envd_port}\n"
    )
}

/// Docker's default capability set, without `CAP_NET_RAW`.
const CAPABILITIES: &[&str] = &[
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

const CPU_PERIOD_US: u64 = 100_000;

/// A drive mounted on the host and bound into the container.
pub(super) struct DriveBind {
    pub source: std::path::PathBuf,
    pub destination: std::path::PathBuf,
    pub read_only: bool,
}

pub(super) struct BundleSpec<'a> {
    pub work_dir: &'a Path,
    pub hostname: &'a str,
    pub guest_ip: Ipv4Addr,
    pub nameservers: &'a [Ipv4Addr],
    pub resources: SandboxResources,
    pub pids_limit: u32,
    pub envd_port: u16,
    pub cgroups_path: &'a str,
    pub drives: &'a [DriveBind],
}

/// Writes `init.sh`, the /etc files and `config.json` into the work directory.
pub(super) fn write_bundle(spec: &BundleSpec<'_>) -> Result<()> {
    let dir = spec.work_dir;
    fs::create_dir_all(dir.join("etc")).context("create bundle etc directory")?;
    fs::write(dir.join("init.sh"), INIT_SCRIPT).context("write container init")?;
    fs::write(dir.join("inittab"), inittab(spec.envd_port)).context("write inittab")?;
    let resolv: String = spec
        .nameservers
        .iter()
        .map(|server| format!("nameserver {server}\n"))
        .collect();
    fs::write(dir.join("etc/resolv.conf"), resolv).context("write resolv.conf")?;
    fs::write(
        dir.join("etc/hosts"),
        format!(
            "127.0.0.1 localhost\n::1 localhost\n{} {}\n",
            spec.guest_ip, spec.hostname
        ),
    )
    .context("write hosts")?;
    fs::write(dir.join("etc/hostname"), format!("{}\n", spec.hostname))
        .context("write hostname")?;
    let config = serde_json::to_vec_pretty(&oci_config(spec)).context("encode config.json")?;
    fs::write(dir.join("config.json"), config).context("write config.json")
}

fn bind(destination: &str, source: &Path, read_only: bool) -> Value {
    let mut options = vec!["rbind", "nosuid", "nodev"];
    if read_only {
        options.push("ro");
    }
    json!({"destination": destination, "type": "bind", "source": source, "options": options})
}

pub(super) fn oci_config(spec: &BundleSpec<'_>) -> Value {
    let dir = spec.work_dir;
    let drive_mounts: Vec<Value> = spec
        .drives
        .iter()
        .map(|drive| {
            bind(
                drive.destination.to_str().unwrap_or_default(),
                &drive.source,
                drive.read_only,
            )
        })
        .collect();
    let memory_bytes = u64::from(spec.resources.memory_mib) * 1024 * 1024;
    let cpu_quota = u64::from(spec.resources.cpu_count.max(1)) * CPU_PERIOD_US;
    let mut config = json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/agentenv/bin/busybox", "init"],
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/root",
            ],
            "cwd": "/",
            "capabilities": {
                "bounding": CAPABILITIES,
                "effective": CAPABILITIES,
                "permitted": CAPABILITIES,
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1_048_576u64, "soft": 1_048_576u64}],
            "noNewPrivileges": true
        },
        "root": {"path": dir.join("rootfs"), "readonly": false},
        "hostname": spec.hostname,
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts",
             "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
             "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
            {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
             "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
             "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]},
            {"destination": "/run", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "nodev", "mode=755"]},
            bind("/agentenv", &dir.join("tools/agentenv"), true),
            bind("/.aenv-init", &dir.join("init.sh"), true),
            bind("/etc/inittab", &dir.join("inittab"), true),
            bind("/etc/resolv.conf", &dir.join("etc/resolv.conf"), true),
            bind("/etc/hosts", &dir.join("etc/hosts"), true),
            bind("/etc/hostname", &dir.join("etc/hostname"), true)
        ],
        "linux": {
            "cgroupsPath": spec.cgroups_path,
            "resources": {
                "memory": {"limit": memory_bytes, "swap": memory_bytes},
                "cpu": {"quota": cpu_quota, "period": CPU_PERIOD_US},
                "pids": {"limit": spec.pids_limit}
            },
            "namespaces": [
                {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
                {"type": "cgroup"},
                {"type": "network", "path": dir.join("netns")}
            ],
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
                "/proc/sched_debug", "/sys/firmware", "/proc/scsi"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    });
    config["mounts"]
        .as_array_mut()
        .expect("mounts is an array")
        .extend(drive_mounts);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMESERVERS: &[Ipv4Addr] = &[Ipv4Addr::new(10, 0, 0, 53)];

    fn spec(dir: &Path) -> BundleSpec<'_> {
        BundleSpec {
            work_dir: dir,
            hostname: "instance",
            guest_ip: Ipv4Addr::new(169, 254, 0, 21),
            nameservers: NAMESERVERS,
            resources: SandboxResources {
                cpu_count: 2,
                memory_mib: 512,
                disk_size_mib: 0,
            },
            pids_limit: 4096,
            envd_port: 49983,
            cgroups_path: "/aenv-container/aenv-x",
            drives: DRIVES,
        }
    }

    static DRIVES: &[DriveBind] = &[];

    #[test]
    fn drives_are_bound_after_the_base_mounts() {
        let drives = [DriveBind {
            source: "/work/sb/drives/data/sub".into(),
            destination: "/data".into(),
            read_only: true,
        }];
        let mut spec = spec(Path::new("/work/sb"));
        spec.drives = &drives;
        let config = oci_config(&spec);
        let mounts = config["mounts"].as_array().unwrap();
        let last = mounts.last().unwrap();
        assert_eq!(last["destination"], "/data");
        assert_eq!(last["source"], "/work/sb/drives/data/sub");
        assert!(last["options"].as_array().unwrap().contains(&json!("ro")));
    }

    #[test]
    fn config_maps_resources_namespaces_and_tools() {
        let dir = Path::new("/work/sb");
        let config = oci_config(&spec(dir));
        assert_eq!(config["root"]["path"], "/work/sb/rootfs");
        let resources = &config["linux"]["resources"];
        assert_eq!(resources["memory"]["limit"], 512u64 * 1024 * 1024);
        assert_eq!(resources["cpu"]["quota"], 200_000u64);
        assert_eq!(resources["pids"]["limit"], 4096);
        let netns = config["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|ns| ns["type"] == "network")
            .unwrap();
        assert_eq!(netns["path"], "/work/sb/netns");
        let tools = config["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/agentenv")
            .unwrap();
        assert_eq!(tools["source"], "/work/sb/tools/agentenv");
        assert!(tools["options"].as_array().unwrap().contains(&json!("ro")));
        let caps = config["process"]["capabilities"]["bounding"]
            .as_array()
            .unwrap();
        assert!(!caps.contains(&json!("CAP_NET_RAW")));
        assert!(!caps.contains(&json!("CAP_SYS_ADMIN")));
        assert_eq!(
            config["process"]["args"],
            json!(["/agentenv/bin/busybox", "init"])
        );
    }

    #[test]
    fn writes_bundle_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_bundle(&spec(temp.path()))?;
        assert!(fs::read_to_string(temp.path().join("init.sh"))?.contains("/etc/passwd"));
        let inittab = fs::read_to_string(temp.path().join("inittab"))?;
        assert!(inittab.contains("::sysinit:/agentenv/bin/busybox sh /.aenv-init"));
        assert!(inittab.contains("::respawn:/agentenv/envd -isnotfc -port 49983"));
        assert_eq!(
            fs::read_to_string(temp.path().join("etc/resolv.conf"))?,
            "nameserver 10.0.0.53\n"
        );
        assert!(
            fs::read_to_string(temp.path().join("etc/hosts"))?.contains("169.254.0.21 instance")
        );
        let config: Value = serde_json::from_slice(&fs::read(temp.path().join("config.json"))?)?;
        assert_eq!(config["hostname"], "instance");
        Ok(())
    }
}
