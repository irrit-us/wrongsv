use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::{WireGuardForwardConfig, WireGuardPeerConfig, WireGuardServerConfig};

use super::ShutdownSignal;

#[derive(Clone, Debug)]
pub(crate) struct WireGuardConfig {
    pub listen: String,
    pub private_key: String,
    pub mtu: u32,
    pub server_cidrs: Vec<String>,
    pub routes: Vec<String>,
    pub peers: Vec<WireGuardPeer>,
    pub forwards: Vec<WireGuardForward>,
    pub outbound: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct WireGuardPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub email: Option<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct WireGuardForward {
    pub service: String,
    pub target: String,
}

#[derive(Serialize)]
struct WireGuardRuntimeConfig<'a> {
    listen: &'a str,
    private_key: &'a str,
    mtu: u32,
    server_cidrs: &'a [String],
    routes: &'a [String],
    peers: Vec<WireGuardRuntimePeer<'a>>,
    forwards: Vec<WireGuardRuntimeForward<'a>>,
    outbound: bool,
}

#[derive(Serialize)]
struct WireGuardRuntimePeer<'a> {
    public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preshared_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    allowed_ips: &'a [String],
}

#[derive(Serialize)]
struct WireGuardRuntimeForward<'a> {
    service: &'a str,
    target: &'a str,
}

pub(crate) fn parse_wireguard_config(
    listen: &str,
    wc: &WireGuardServerConfig,
) -> Result<WireGuardConfig, String> {
    Ok(WireGuardConfig {
        listen: listen.to_string(),
        private_key: wc.private_key.trim().to_string(),
        mtu: wc.mtu.max(576),
        server_cidrs: wc
            .server_cidrs
            .iter()
            .map(|value| value.trim().to_string())
            .collect(),
        routes: wc
            .routes
            .iter()
            .map(|value| value.trim().to_string())
            .collect(),
        peers: wc
            .peers
            .iter()
            .map(parse_wireguard_peer)
            .collect::<Result<Vec<_>, _>>()?,
        forwards: wc
            .forwards
            .iter()
            .map(parse_wireguard_forward)
            .collect::<Result<Vec<_>, _>>()?,
        outbound: wc.outbound,
    })
}

fn parse_wireguard_peer(peer: &WireGuardPeerConfig) -> Result<WireGuardPeer, String> {
    Ok(WireGuardPeer {
        public_key: peer.public_key.trim().to_string(),
        preshared_key: peer
            .preshared_key
            .as_ref()
            .map(|value| value.trim().to_string()),
        email: peer
            .email
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        allowed_ips: peer
            .allowed_ips
            .iter()
            .map(|value| value.trim().to_string())
            .collect(),
    })
}

fn parse_wireguard_forward(forward: &WireGuardForwardConfig) -> Result<WireGuardForward, String> {
    Ok(WireGuardForward {
        service: forward.service.trim().to_string(),
        target: forward.target.trim().to_string(),
    })
}

pub(crate) fn run_wireguard_endpoint(
    config: WireGuardConfig,
    shutdown: ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error>> {
    let helper_binary = build_wireguard_helper()?;
    let runtime_config = write_runtime_config(&config)?;
    let mut child = spawn_wireguard_helper(&helper_binary, &runtime_config)?;

    match wait_for_helper_start(&mut child, Duration::from_secs(3))? {
        Some(status) => {
            let _ = fs::remove_file(&runtime_config);
            return Err(format!("wireguard helper exited during startup: {status}").into());
        }
        None => {}
    }

    loop {
        if shutdown.is_shutdown_requested() {
            terminate_child(&mut child)?;
            let _ = fs::remove_file(&runtime_config);
            return Ok(());
        }

        if let Some(status) = child.try_wait()? {
            let _ = fs::remove_file(&runtime_config);
            return Err(format!("wireguard helper exited unexpectedly: {status}").into());
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn build_wireguard_helper() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let helper_dir = helper_directory();
    let output = helper_binary_path();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    let status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&output)
        .arg(".")
        .current_dir(&helper_dir)
        .status()?;

    if !status.success() {
        return Err(format!("go build failed for {}", helper_dir.display()).into());
    }

    Ok(output)
}

fn spawn_wireguard_helper(
    binary: &Path,
    runtime_config: &Path,
) -> Result<Child, Box<dyn std::error::Error>> {
    let child = Command::new(binary)
        .arg("--config")
        .arg(runtime_config)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn wait_for_helper_start(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn terminate_child(child: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let _ = child.stdin.take();
    for _ in 0..10 {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    child.kill()?;
    let _ = child.wait();
    Ok(())
}

fn write_runtime_config(config: &WireGuardConfig) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let runtime = WireGuardRuntimeConfig {
        listen: &config.listen,
        private_key: &config.private_key,
        mtu: config.mtu,
        server_cidrs: &config.server_cidrs,
        routes: &config.routes,
        peers: config
            .peers
            .iter()
            .map(|peer| WireGuardRuntimePeer {
                public_key: &peer.public_key,
                preshared_key: peer.preshared_key.as_deref(),
                email: peer.email.as_deref(),
                allowed_ips: &peer.allowed_ips,
            })
            .collect(),
        forwards: config
            .forwards
            .iter()
            .map(|forward| WireGuardRuntimeForward {
                service: &forward.service,
                target: &forward.target,
            })
            .collect(),
        outbound: config.outbound,
    };

    let path = runtime_config_path();
    fs::write(&path, serde_json::to_vec_pretty(&runtime)?)?;
    Ok(path)
}

fn helper_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../helpers/wireguard-service-bridge")
}

fn helper_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/wireguard-service-bridge")
}

fn runtime_config_path() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("wrongsv-wireguard-{stamp}.json"))
}
