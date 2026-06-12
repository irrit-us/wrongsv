//! Per-user usage and system metrics for wrongsv.
//!
//! [`Registry`] is the central counter store. Handlers call
//! [`Registry::record_bytes_in`] / [`Registry::record_bytes_out`] when relaying
//! bytes for a known user (identified by email), and hold a [`ConnectionGuard`]
//! from [`Registry::connection_started`] for the lifetime of a connection.
//!
//! [`Registry::render_prometheus`] dumps all counters in Prometheus text
//! exposition format. Pair it with [`serve`] to expose the dump over HTTP.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

pub mod config;
pub mod server;

pub use config::MetricsConfig;
pub use server::{ServerHandle, serve};

/// Stats tracked for one user (keyed by email).
#[derive(Debug, Default)]
struct UserStats {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active_conns: AtomicI64,
    total_conns: AtomicU64,
}

/// Snapshot of one user's counters at a point in time.
#[derive(Debug, Clone)]
pub struct UserSnapshot {
    pub email: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_connections: i64,
    pub total_connections: u64,
}

/// Thread-safe usage registry. Cheap to `Arc::clone`.
pub struct Registry {
    users: RwLock<HashMap<String, Arc<UserStats>>>,
    total_bytes_in: AtomicU64,
    total_bytes_out: AtomicU64,
    total_conns: AtomicU64,
    started_at: Instant,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            total_conns: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    fn get_or_create(&self, email: &str) -> Arc<UserStats> {
        if let Some(stats) = self
            .users
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(email)
        {
            return Arc::clone(stats);
        }
        let mut writer = self.users.write().unwrap_or_else(|e| e.into_inner());
        let entry = writer
            .entry(email.to_string())
            .or_insert_with(|| Arc::new(UserStats::default()));
        Arc::clone(entry)
    }

    /// Increment bytes received from the client toward the user's quota.
    pub fn record_bytes_in(&self, email: &str, n: u64) {
        if email.is_empty() || n == 0 {
            return;
        }
        self.get_or_create(email)
            .bytes_in
            .fetch_add(n, Ordering::Relaxed);
        self.total_bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment bytes sent back to the client from the upstream target.
    pub fn record_bytes_out(&self, email: &str, n: u64) {
        if email.is_empty() || n == 0 {
            return;
        }
        self.get_or_create(email)
            .bytes_out
            .fetch_add(n, Ordering::Relaxed);
        self.total_bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Mark a new connection as open for this user. Drop the returned guard
    /// when the connection closes — the active-connections counter is RAII.
    pub fn connection_started(self: &Arc<Self>, email: &str) -> ConnectionGuard {
        if email.is_empty() {
            return ConnectionGuard { stats: None };
        }
        let stats = self.get_or_create(email);
        stats.active_conns.fetch_add(1, Ordering::Relaxed);
        stats.total_conns.fetch_add(1, Ordering::Relaxed);
        self.total_conns.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard { stats: Some(stats) }
    }

    /// Snapshot every user's current counters. Order is unspecified.
    pub fn snapshot(&self) -> Vec<UserSnapshot> {
        let users = self.users.read().unwrap_or_else(|e| e.into_inner());
        users
            .iter()
            .map(|(email, stats)| UserSnapshot {
                email: email.clone(),
                bytes_in: stats.bytes_in.load(Ordering::Relaxed),
                bytes_out: stats.bytes_out.load(Ordering::Relaxed),
                active_connections: stats.active_conns.load(Ordering::Relaxed),
                total_connections: stats.total_conns.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Uptime in seconds since the registry was created.
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Render every counter as a Prometheus text-format exposition.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP wrongsv_uptime_seconds Uptime of the wrongsv server in seconds\n");
        out.push_str("# TYPE wrongsv_uptime_seconds counter\n");
        out.push_str(&format!(
            "wrongsv_uptime_seconds {}\n",
            self.uptime_seconds()
        ));
        out.push_str("# HELP wrongsv_total_bytes_in Total bytes received from clients\n");
        out.push_str("# TYPE wrongsv_total_bytes_in counter\n");
        out.push_str(&format!(
            "wrongsv_total_bytes_in {}\n",
            self.total_bytes_in.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP wrongsv_total_bytes_out Total bytes sent back to clients\n");
        out.push_str("# TYPE wrongsv_total_bytes_out counter\n");
        out.push_str(&format!(
            "wrongsv_total_bytes_out {}\n",
            self.total_bytes_out.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP wrongsv_total_connections Total connections accepted\n");
        out.push_str("# TYPE wrongsv_total_connections counter\n");
        out.push_str(&format!(
            "wrongsv_total_connections {}\n",
            self.total_conns.load(Ordering::Relaxed)
        ));

        let snaps = self.snapshot();
        if !snaps.is_empty() {
            out.push_str("# HELP wrongsv_user_bytes_in Bytes received from a user\n");
            out.push_str("# TYPE wrongsv_user_bytes_in counter\n");
            for s in &snaps {
                out.push_str(&format!(
                    "wrongsv_user_bytes_in{{email=\"{}\"}} {}\n",
                    escape_label(&s.email),
                    s.bytes_in
                ));
            }
            out.push_str("# HELP wrongsv_user_bytes_out Bytes sent back to a user\n");
            out.push_str("# TYPE wrongsv_user_bytes_out counter\n");
            for s in &snaps {
                out.push_str(&format!(
                    "wrongsv_user_bytes_out{{email=\"{}\"}} {}\n",
                    escape_label(&s.email),
                    s.bytes_out
                ));
            }
            out.push_str("# HELP wrongsv_user_active_connections Active connections per user\n");
            out.push_str("# TYPE wrongsv_user_active_connections gauge\n");
            for s in &snaps {
                out.push_str(&format!(
                    "wrongsv_user_active_connections{{email=\"{}\"}} {}\n",
                    escape_label(&s.email),
                    s.active_connections
                ));
            }
            out.push_str("# HELP wrongsv_user_total_connections Total connections per user\n");
            out.push_str("# TYPE wrongsv_user_total_connections counter\n");
            for s in &snaps {
                out.push_str(&format!(
                    "wrongsv_user_total_connections{{email=\"{}\"}} {}\n",
                    escape_label(&s.email),
                    s.total_connections
                ));
            }
        }
        out
    }
}

/// RAII guard returned by [`Registry::connection_started`]. When dropped, the
/// user's active-connections gauge is decremented.
pub struct ConnectionGuard {
    stats: Option<Arc<UserStats>>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(stats) = &self.stats {
            stats.active_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Escape a Prometheus label value per text exposition format:
/// `\` → `\\`, `"` → `\"`, `\n` → `\n` (literal backslash-n).
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_renders_system_metrics() {
        let r = Registry::new();
        let out = r.render_prometheus();
        assert!(out.contains("wrongsv_uptime_seconds"));
        assert!(out.contains("wrongsv_total_bytes_in 0"));
        assert!(out.contains("wrongsv_total_bytes_out 0"));
        assert!(out.contains("wrongsv_total_connections 0"));
        assert!(!out.contains("wrongsv_user_bytes_in{"));
    }

    #[test]
    fn record_bytes_in_increments_user_and_total() {
        let r = Registry::new();
        r.record_bytes_in("alice@test", 100);
        r.record_bytes_in("alice@test", 50);
        r.record_bytes_in("bob@test", 25);
        let snaps = r.snapshot();
        assert_eq!(snaps.len(), 2);
        let alice = snaps.iter().find(|s| s.email == "alice@test").unwrap();
        let bob = snaps.iter().find(|s| s.email == "bob@test").unwrap();
        assert_eq!(alice.bytes_in, 150);
        assert_eq!(bob.bytes_in, 25);
        let out = r.render_prometheus();
        assert!(out.contains("wrongsv_total_bytes_in 175"));
    }

    #[test]
    fn record_bytes_out_increments_independently() {
        let r = Registry::new();
        r.record_bytes_in("u", 10);
        r.record_bytes_out("u", 20);
        let snap = &r.snapshot()[0];
        assert_eq!(snap.bytes_in, 10);
        assert_eq!(snap.bytes_out, 20);
    }

    #[test]
    fn zero_or_empty_email_does_not_create_entry() {
        let r = Registry::new();
        r.record_bytes_in("", 100); // empty email ignored
        r.record_bytes_in("u", 0); // zero bytes ignored
        let snaps = r.snapshot();
        assert_eq!(snaps.len(), 0);
    }

    #[test]
    fn connection_guard_increments_then_decrements_active() {
        let r = Arc::new(Registry::new());
        let g1 = r.connection_started("alice");
        let g2 = r.connection_started("alice");
        let snap = r.snapshot();
        let alice = snap.iter().find(|s| s.email == "alice").unwrap();
        assert_eq!(alice.active_connections, 2);
        assert_eq!(alice.total_connections, 2);
        drop(g1);
        let snap = r.snapshot();
        let alice = snap.iter().find(|s| s.email == "alice").unwrap();
        assert_eq!(alice.active_connections, 1);
        assert_eq!(alice.total_connections, 2);
        drop(g2);
        let snap = r.snapshot();
        let alice = snap.iter().find(|s| s.email == "alice").unwrap();
        assert_eq!(alice.active_connections, 0);
    }

    #[test]
    fn prometheus_escapes_quotes_and_backslashes_in_email() {
        let r = Registry::new();
        r.record_bytes_in("weird\"name\\here@test", 1);
        let out = r.render_prometheus();
        assert!(out.contains("email=\"weird\\\"name\\\\here@test\""), "got: {out}");
    }

    #[test]
    fn users_isolated() {
        let r = Registry::new();
        r.record_bytes_in("a", 10);
        r.record_bytes_out("b", 20);
        let snaps = r.snapshot();
        let a = snaps.iter().find(|s| s.email == "a").unwrap();
        let b = snaps.iter().find(|s| s.email == "b").unwrap();
        assert_eq!(a.bytes_in, 10);
        assert_eq!(a.bytes_out, 0);
        assert_eq!(b.bytes_in, 0);
        assert_eq!(b.bytes_out, 20);
    }
}
