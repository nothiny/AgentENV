//! Fault injection for integration tests, compiled into debug builds only.
//!
//! `AENV_FAILPOINTS` lists the points to trigger, comma-separated. `name`
//! makes [`fail`] return an error at that point, `name:key` only for that
//! key (for example a drive ID), and `name=ms` makes [`delay`] sleep. Release
//! builds compile every point to a no-op.

/// Errors when `AENV_FAILPOINTS` arms `name`, or `name:key` for this `key`.
pub(crate) fn fail(name: &str, key: Option<&str>) -> anyhow::Result<()> {
    #[cfg(debug_assertions)]
    if armed(name, key) {
        anyhow::bail!("failpoint {name} triggered");
    }
    let _ = (name, key);
    Ok(())
}

/// Sleeps for the milliseconds `AENV_FAILPOINTS` gives `name=ms`.
pub(crate) async fn delay(name: &str) {
    #[cfg(debug_assertions)]
    if let Some(ms) = delay_ms(name) {
        tracing::warn!(failpoint = name, ms, "failpoint delaying");
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    let _ = name;
}

#[cfg(debug_assertions)]
fn spec() -> String {
    std::env::var("AENV_FAILPOINTS").unwrap_or_default()
}

#[cfg(debug_assertions)]
fn entries(spec: &str) -> impl Iterator<Item = &str> {
    spec.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
}

#[cfg(debug_assertions)]
fn armed(name: &str, key: Option<&str>) -> bool {
    armed_in(&spec(), name, key)
}

#[cfg(debug_assertions)]
fn armed_in(spec: &str, name: &str, key: Option<&str>) -> bool {
    entries(spec).any(|entry| match entry.split_once(':') {
        Some((point, wanted)) => point == name && key == Some(wanted),
        None => entry == name,
    })
}

#[cfg(debug_assertions)]
fn delay_ms(name: &str) -> Option<u64> {
    delay_ms_in(&spec(), name)
}

#[cfg(debug_assertions)]
fn delay_ms_in(spec: &str, name: &str) -> Option<u64> {
    entries(spec).find_map(|entry| {
        let (point, ms) = entry.split_once('=')?;
        (point == name).then(|| ms.parse().ok()).flatten()
    })
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    // The spec is passed in, not set in the environment: other tests read
    // the environment from parallel threads.
    #[test]
    fn parses_points_keys_and_delays() {
        let spec = "restack, mount-drive:d2 ,publish=250";
        assert!(armed_in(spec, "restack", None));
        assert!(armed_in(spec, "mount-drive", Some("d2")));
        assert!(!armed_in(spec, "mount-drive", Some("d1")));
        assert!(!armed_in(spec, "mount-drive", None));
        assert_eq!(delay_ms_in(spec, "publish"), Some(250));
        assert_eq!(delay_ms_in(spec, "restack"), None);
        assert!(!armed_in("", "restack", None));
    }
}
