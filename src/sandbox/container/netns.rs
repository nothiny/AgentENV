//! Network for a container sandbox: a namespace of its own, joined to a
//! leased slot by a veth pair that takes the place of the slot's `tap0`.
//!
//! The slot-side end keeps the name `tap0`, so the slot's forwarding,
//! anti-spoofing and egress rules apply to the container as they do to a VM.
//! A slot modified this way is destroyed on release rather than pooled.

use std::fs::{self, File};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use anyhow::{anyhow, bail, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};

/// Guest link addresses, as returned by `Slot::guest_link`.
#[derive(Clone, Copy, Debug)]
pub(super) struct GuestLink {
    pub tap_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix: u8,
}

/// Creates a persistent network namespace bound at `path`.
pub(super) fn create_netns(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create netns directory {}", parent.display()))?;
    }
    File::create(path).with_context(|| format!("create netns file {}", path.display()))?;
    let target = path.to_path_buf();
    // Namespace membership is per thread: unshare on a throwaway thread so
    // the caller's thread stays in its own namespace.
    thread::spawn(move || -> Result<()> {
        unshare(CloneFlags::CLONE_NEWNET).context("unshare(CLONE_NEWNET)")?;
        mount(
            Some("/proc/thread-self/ns/net"),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("bind netns to {}", target.display()))?;
        Ok(())
    })
    .join()
    .map_err(|panic| anyhow!("netns creation thread panicked: {panic:?}"))?
}

/// Unmounts and removes the namespace at `path`. Missing is success.
pub(super) fn remove_netns(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    while super::is_mount_point(path)? {
        umount2(path, MntFlags::MNT_DETACH)
            .with_context(|| format!("unmount netns {}", path.display()))?;
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove netns file {}", path.display())),
    }
}

fn ip_in(netns: &Path, args: &[&str]) -> Result<()> {
    let mut net = std::ffi::OsString::from("--net=");
    net.push(netns);
    let output = Command::new("nsenter")
        .arg(&net)
        .arg("ip")
        .args(args)
        .output()
        .context("spawn nsenter ip")?;
    if !output.status.success() {
        bail!(
            "ip {} in {}: {}",
            args.join(" "),
            netns.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Replaces the slot's `tap0` with a veth pair whose other end becomes `eth0`
/// in `guest_netns`, and configures both ends and the guest default route.
pub(super) fn attach_guest(slot_netns: &Path, guest_netns: &Path, link: GuestLink) -> Result<()> {
    let guest: PathBuf = guest_netns.to_path_buf();
    let guest_str = guest.to_str().context("guest netns path is not UTF-8")?;
    let tap = format!("{}/{}", link.tap_ip, link.prefix);
    let addr = format!("{}/{}", link.guest_ip, link.prefix);
    let tap_ip = link.tap_ip.to_string();

    ip_in(slot_netns, &["link", "del", "tap0"])?;
    ip_in(
        slot_netns,
        &[
            "link", "add", "tap0", "type", "veth", "peer", "name", "eth0", "netns", guest_str,
        ],
    )?;
    ip_in(slot_netns, &["addr", "add", &tap, "dev", "tap0"])?;
    ip_in(slot_netns, &["link", "set", "tap0", "up"])?;
    ip_in(&guest, &["link", "set", "lo", "up"])?;
    ip_in(&guest, &["addr", "add", &addr, "dev", "eth0"])?;
    ip_in(&guest, &["link", "set", "eth0", "up"])?;
    ip_in(&guest, &["route", "add", "default", "via", &tap_ip])?;
    Ok(())
}
