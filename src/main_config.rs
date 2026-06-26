use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Debug, clap::Args)]
#[command(after_long_help = "\
Supported cooperative clusters:
  reality-vision        vless + reality + vision
  anytls-vision         vless + anytls + vision
  tls-vision            vless + tls + vision
  ws-tcp                vless + websocket
  httpupgrade           vless + httpupgrade
  grpc                  vless + grpc
  xhttp                 vless + xhttp
  vless-raw             vless raw tcp
  hysteria2-gecko       hysteria2 + gecko obfs
  hysteria2-salamander  hysteria2 + salamander obfs
  tuic                  tuic
  trojan-tls            trojan over tls
  shadowsocks-2022      shadowsocks 2022 method
  shadowsocks-aead      shadowsocks AEAD method
  vmess                 vmess
  naive                 naive h2 CONNECT over TLS

Component form also works with comma or plus separators, for example:
  --cluster anytls,vision
  --cluster reality+vision

Mutually exclusive clusters such as anytls-reality or
reality-vision,anytls-vision are rejected.")]
pub(crate) struct GenerateMainConfigArgs {
    /// Cooperative protocol component cluster, e.g. reality,vision or anytls-vision
    #[arg(long, alias = "protocol-cluster", default_value = "reality-vision")]
    pub cluster: String,
    /// Write a single TOML file to this path
    #[arg(long, conflicts_with = "output_dir")]
    pub output: Option<PathBuf>,
    /// Write TOML plus manifest files to this directory
    #[arg(long, value_name = "DIR", conflicts_with = "output")]
    pub output_dir: Option<PathBuf>,
    /// Skip manifest.json when writing a directory output
    #[arg(long)]
    pub no_manifest: bool,
    /// Listener address for the generated server config
    #[arg(long, default_value = "0.0.0.0:443")]
    pub listen: String,
    /// User email / metrics key
    #[arg(long, default_value = "user@example.com")]
    pub email: String,
    /// REALITY fallback/spider destination
    #[arg(long, alias = "dest", default_value = "www.microsoft.com:443")]
    pub reality_dest: String,
    /// Probe fallback destination for TLS-like protocols
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub fallback_dest: String,
    /// Shadowsocks method for shadowsocks-2022 clusters
    #[arg(long, default_value = "2022-blake3-aes-128-gcm")]
    pub shadowsocks_method: String,
    /// TUIC congestion control
    #[arg(long, default_value = "cubic")]
    pub tuic_congestion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsLayer {
    Reality,
    AnyTls,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    WebSocket,
    HttpUpgrade,
    Grpc,
    Xhttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inbound {
    Vless,
    Shadowsocks2022,
    ShadowsocksAead,
    Trojan,
    Hysteria2,
    Tuic,
    Vmess,
    Naive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HysteriaObfs {
    Gecko,
    Salamander,
}

#[derive(Debug, Default)]
struct ComponentSet {
    inbound: Option<Inbound>,
    tls_layer: Option<TlsLayer>,
    framing: Option<Framing>,
    hysteria_obfs: Option<HysteriaObfs>,
    vision: bool,
}

struct RenderedConfig {
    canonical: String,
    filename: String,
    content: String,
    values: serde_json::Value,
}

pub(crate) fn run(args: GenerateMainConfigArgs) -> Result<(), String> {
    let components = ComponentSet::parse(&args.cluster)?;
    let rendered = render_config(&components, &args)?;
    validate_rendered(&rendered.content)?;

    if let Some(output) = &args.output {
        write_file(output, &rendered.content)?;
        println!(
            "{}",
            serde_json::json!({
                "cluster": args.cluster,
                "canonical": rendered.canonical,
                "path": output,
            })
        );
        return Ok(());
    }

    let output_dir = args.output_dir.unwrap_or_else(|| {
        PathBuf::from("generated-configs").join(format!(
            "{}-{}",
            rendered.canonical,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ))
    });
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("failed to create {}: {e}", output_dir.display()))?;
    let config_path = output_dir.join(&rendered.filename);
    write_file(&config_path, &rendered.content)?;
    if !args.no_manifest {
        write_file(
            &output_dir.join("manifest.json"),
            &serde_json::to_string_pretty(&serde_json::json!({
                "generatedAtUnix": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                "cluster": args.cluster,
                "canonical": rendered.canonical,
                "listen": args.listen,
                "file": {
                    "protocol": rendered.canonical,
                    "path": config_path,
                    "values": rendered.values,
                },
            }))
            .map_err(|e| format!("failed to serialize manifest: {e}"))?,
        )?;
    }
    write_file(
        &output_dir.join("README.md"),
        &format!(
            "# generated wrongsv main config\n\n- {}: {}\n",
            rendered.canonical, rendered.filename
        ),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "outputDir": output_dir,
            "files": [config_path],
            "manifestWritten": !args.no_manifest,
        }))
        .map_err(|e| format!("failed to serialize output: {e}"))?
    );
    Ok(())
}

fn validate_rendered(content: &str) -> Result<(), String> {
    let config: wrongsv_server::Config =
        toml::from_str(content).map_err(|e| format!("generated TOML is invalid: {e}"))?;
    config
        .validate()
        .map_err(|e| format!("generated config is not accepted by wrongsv: {e}"))
}

fn write_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    write_private_file(path, format!("{}\n", content.trim_end()).as_bytes())
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to restrict permissions on {}: {e}", path.display()))?;
    file.write_all(content)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &[u8]) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

impl ComponentSet {
    fn parse(cluster: &str) -> Result<Self, String> {
        let tokens = expand_cluster(cluster)?;
        let mut set = ComponentSet::default();
        for token in tokens {
            set.add(&token)?;
        }
        set.validate(cluster)?;
        Ok(set)
    }

    fn add(&mut self, token: &str) -> Result<(), String> {
        match token {
            "vless" => self.set_inbound(Inbound::Vless),
            "reality" => self.set_tls_layer(TlsLayer::Reality),
            "anytls" => self.set_tls_layer(TlsLayer::AnyTls),
            "tls" => self.set_tls_layer(TlsLayer::Tls),
            "vision" => {
                self.vision = true;
                Ok(())
            }
            "websocket" | "ws" => self.set_framing(Framing::WebSocket),
            "httpupgrade" => self.set_framing(Framing::HttpUpgrade),
            "grpc" => self.set_framing(Framing::Grpc),
            "xhttp" => self.set_framing(Framing::Xhttp),
            "shadowsocks-2022" => self.set_inbound(Inbound::Shadowsocks2022),
            "shadowsocks-aead" | "shadowsocks" => self.set_inbound(Inbound::ShadowsocksAead),
            "trojan" => self.set_inbound(Inbound::Trojan),
            "hysteria2" => self.set_inbound(Inbound::Hysteria2),
            "tuic" => self.set_inbound(Inbound::Tuic),
            "vmess" => self.set_inbound(Inbound::Vmess),
            "naive" => self.set_inbound(Inbound::Naive),
            "gecko" => self.set_hysteria_obfs(HysteriaObfs::Gecko),
            "salamander" => self.set_hysteria_obfs(HysteriaObfs::Salamander),
            "raw" | "tcp" => Ok(()),
            other => Err(format!("unknown protocol component or preset: {other}")),
        }
    }

    fn set_inbound(&mut self, inbound: Inbound) -> Result<(), String> {
        match self.inbound {
            Some(existing) if existing != inbound => Err(format!(
                "inbound protocols are mutually exclusive: {} + {}",
                inbound_name(existing),
                inbound_name(inbound)
            )),
            _ => {
                self.inbound = Some(inbound);
                Ok(())
            }
        }
    }

    fn set_tls_layer(&mut self, layer: TlsLayer) -> Result<(), String> {
        match self.tls_layer {
            Some(existing) if existing != layer => Err(format!(
                "TLS-layer components are mutually exclusive: {} + {}",
                tls_layer_name(existing),
                tls_layer_name(layer)
            )),
            _ => {
                self.tls_layer = Some(layer);
                Ok(())
            }
        }
    }

    fn set_framing(&mut self, framing: Framing) -> Result<(), String> {
        match self.framing {
            Some(existing) if existing != framing => Err(format!(
                "stream-framing components are mutually exclusive: {} + {}",
                framing_name(existing),
                framing_name(framing)
            )),
            _ => {
                self.framing = Some(framing);
                Ok(())
            }
        }
    }

    fn set_hysteria_obfs(&mut self, obfs: HysteriaObfs) -> Result<(), String> {
        match self.hysteria_obfs {
            Some(existing) if existing != obfs => Err(format!(
                "hysteria2 obfs components are mutually exclusive: {} + {}",
                hysteria_obfs_name(existing),
                hysteria_obfs_name(obfs)
            )),
            _ => {
                self.hysteria_obfs = Some(obfs);
                Ok(())
            }
        }
    }

    fn validate(&mut self, original: &str) -> Result<(), String> {
        if self.tls_layer.is_some() || self.framing.is_some() || self.vision {
            if matches!(self.inbound, Some(inbound) if inbound != Inbound::Vless) {
                return Err(format!(
                    "cluster {original:?} mixes VLESS transport components with a non-VLESS inbound"
                ));
            }
            self.inbound = Some(Inbound::Vless);
        }
        let inbound = self
            .inbound
            .ok_or_else(|| format!("cluster {original:?} does not select an inbound protocol"))?;

        if inbound != Inbound::Vless {
            if self.tls_layer.is_some() || self.framing.is_some() || self.vision {
                return Err(format!(
                    "cluster {original:?} combines non-cooperating non-VLESS and VLESS components"
                ));
            }
            if self.hysteria_obfs.is_some() && inbound != Inbound::Hysteria2 {
                return Err("hysteria2 obfs components require hysteria2".into());
            }
            if inbound == Inbound::Hysteria2 && self.hysteria_obfs.is_none() {
                self.hysteria_obfs = Some(HysteriaObfs::Gecko);
            }
            return Ok(());
        }

        if self.hysteria_obfs.is_some() {
            return Err("hysteria2 obfs components cannot be combined with VLESS".into());
        }
        if self.tls_layer.is_some() && self.framing.is_some() {
            return Err(format!(
                "cluster {original:?} combines TLS-layer and stream-framing VLESS transports; wrongsv configs allow only one transport layer"
            ));
        }
        if self.vision && self.tls_layer.is_none() {
            return Err("vision requires one TLS-layer component: reality, anytls, or tls".into());
        }
        Ok(())
    }

    fn canonical(&self) -> String {
        match self.inbound.expect("validated inbound") {
            Inbound::Shadowsocks2022 => "shadowsocks-2022".into(),
            Inbound::ShadowsocksAead => "shadowsocks-aead".into(),
            Inbound::Trojan => "trojan-tls".into(),
            Inbound::Hysteria2 => match self.hysteria_obfs.unwrap_or(HysteriaObfs::Gecko) {
                HysteriaObfs::Gecko => "hysteria2-gecko".into(),
                HysteriaObfs::Salamander => "hysteria2-salamander".into(),
            },
            Inbound::Tuic => "tuic".into(),
            Inbound::Vmess => "vmess".into(),
            Inbound::Naive => "naive".into(),
            Inbound::Vless => {
                if let Some(framing) = self.framing {
                    return match framing {
                        Framing::WebSocket => "ws-tcp".into(),
                        Framing::HttpUpgrade => "httpupgrade".into(),
                        Framing::Grpc => "grpc".into(),
                        Framing::Xhttp => "xhttp".into(),
                    };
                }
                let mut parts = Vec::new();
                if let Some(layer) = self.tls_layer {
                    parts.push(tls_layer_name(layer));
                }
                if self.vision {
                    parts.push("vision");
                }
                if parts.is_empty() {
                    "vless-raw".into()
                } else {
                    parts.join("-")
                }
            }
        }
    }
}

fn expand_cluster(cluster: &str) -> Result<Vec<String>, String> {
    let normalized = cluster.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "flclash-stealth" => {
            return Err("cluster \"flclash-stealth\" expands to multiple mutually exclusive configs; generate one cooperative cluster at a time, e.g. reality-vision, anytls-vision, or hysteria2-gecko".into());
        }
        "anytls-reality" | "reality-anytls" => {
            return Err("anytls and reality are mutually exclusive TLS-layer components in one wrongsv main config".into());
        }
        "reality" | "reality-vision" => return Ok(tokens(&["vless", "reality", "vision"])),
        "anytls" | "anytls-vision" => return Ok(tokens(&["vless", "anytls", "vision"])),
        "tls-vision" => return Ok(tokens(&["vless", "tls", "vision"])),
        "ws-tcp" | "websocket" => return Ok(tokens(&["vless", "websocket"])),
        "httpupgrade" => return Ok(tokens(&["vless", "httpupgrade"])),
        "grpc" => return Ok(tokens(&["vless", "grpc"])),
        "xhttp" => return Ok(tokens(&["vless", "xhttp"])),
        "hysteria2" | "hysteria2-gecko" => return Ok(tokens(&["hysteria2", "gecko"])),
        "hysteria2-salamander" => return Ok(tokens(&["hysteria2", "salamander"])),
        "shadowsocks" | "shadowsocks-2022" => return Ok(tokens(&["shadowsocks-2022"])),
        "shadowsocks-aead" => return Ok(tokens(&["shadowsocks-aead"])),
        "trojan-tls" => return Ok(tokens(&["trojan"])),
        "tuic" => return Ok(tokens(&["tuic"])),
        "vmess" => return Ok(tokens(&["vmess"])),
        "naive" => return Ok(tokens(&["naive"])),
        "vless-raw" => return Ok(tokens(&["vless"])),
        _ => {}
    }

    let separator = if normalized.contains(',') {
        ','
    } else if normalized.contains('+') {
        '+'
    } else {
        '\0'
    };
    if separator == '\0' {
        return Ok(vec![normalized]);
    }
    normalized
        .split(separator)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(expand_cluster)
        .try_fold(Vec::new(), |mut acc, expanded| {
            acc.extend(expanded?);
            Ok(acc)
        })
}

fn render_config(
    components: &ComponentSet,
    args: &GenerateMainConfigArgs,
) -> Result<RenderedConfig, String> {
    let canonical = components.canonical();
    let mut values = serde_json::json!({
        "protocol": canonical,
        "listen": args.listen,
        "email": args.email,
    });
    let content = match components.inbound.expect("validated inbound") {
        Inbound::Vless => render_vless(components, args, &mut values)?,
        Inbound::Shadowsocks2022 => render_shadowsocks(args, &canonical, &mut values, true),
        Inbound::ShadowsocksAead => render_shadowsocks(args, &canonical, &mut values, false),
        Inbound::Trojan => render_trojan(args, &mut values),
        Inbound::Hysteria2 => render_hysteria2(components, args, &mut values),
        Inbound::Tuic => render_tuic(args, &mut values),
        Inbound::Vmess => render_vmess_inbound(args, &mut values),
        Inbound::Naive => render_naive(args, &mut values),
    };
    Ok(RenderedConfig {
        filename: format!("{canonical}.toml"),
        canonical,
        content,
        values,
    })
}

fn render_vless(
    components: &ComponentSet,
    args: &GenerateMainConfigArgs,
    values: &mut serde_json::Value,
) -> Result<String, String> {
    let uuid = uuid_v4();
    values["uuid"] = serde_json::json!(uuid);
    let flow = if components.vision {
        "xtls-rprx-vision"
    } else {
        ""
    };
    let table = match (components.tls_layer, components.framing) {
        (Some(TlsLayer::Reality), None) => {
            let private_key = hex(32);
            let short_id = hex(4);
            values["privateKey"] = serde_json::json!(private_key);
            values["shortId"] = serde_json::json!(short_id);
            values["realityDest"] = serde_json::json!(args.reality_dest);
            format!(
                "[reality]\nprivate_key = {}\nshort_ids = [{}]\nmax_time_diff = 300\ndest = {}\n",
                q(&private_key),
                q(&short_id),
                q(&args.reality_dest)
            )
        }
        (Some(TlsLayer::AnyTls), None) => {
            let password = password_url(32);
            values["password"] = serde_json::json!(password);
            values["fallbackDest"] = serde_json::json!(args.fallback_dest);
            format!(
                "[anytls]\npassword = {}\ndest = {}\npadding_scheme = \"\"\"stop=8\n0=30-30\n1=100-400\n\"\"\"\n",
                q(&password),
                q(&args.fallback_dest)
            )
        }
        (Some(TlsLayer::Tls), None) => {
            values["fallbackDest"] = serde_json::json!(args.fallback_dest);
            format!("[tls]\ndest = {}\n", q(&args.fallback_dest))
        }
        (None, Some(Framing::WebSocket)) => "[websocket]\npath = \"/ws\"\n".into(),
        (None, Some(Framing::HttpUpgrade)) => "[httpupgrade]\npath = \"/up\"\n".into(),
        (None, Some(Framing::Grpc)) => "[grpc]\nservice_name = \"GunService\"\n".into(),
        (None, Some(Framing::Xhttp)) => "[xhttp]\npath = \"/xhttp\"\n".into(),
        (None, None) => String::new(),
        _ => return Err("non-cooperating VLESS components reached renderer".into()),
    };
    Ok(format!(
        "listen = {}\n\n[[users]]\nid = {}\nemail = {}\nflow = {}\n\n{}",
        q(&args.listen),
        q(&uuid),
        q(&args.email),
        q(flow),
        table
    ))
}

fn render_shadowsocks(
    args: &GenerateMainConfigArgs,
    canonical: &str,
    values: &mut serde_json::Value,
    is_2022: bool,
) -> String {
    let method = if is_2022 {
        args.shadowsocks_method.clone()
    } else {
        "chacha20-ietf-poly1305".into()
    };
    let password = psk_for_method(&method);
    values["method"] = serde_json::json!(method);
    values["password"] = serde_json::json!(password);
    values["protocol"] = serde_json::json!(canonical);
    format!(
        "listen = {}\n\n[shadowsocks]\nmethod = {}\npassword = {}\nudp = true\n",
        q(&args.listen),
        q(&method),
        q(&password)
    )
}

fn render_trojan(args: &GenerateMainConfigArgs, values: &mut serde_json::Value) -> String {
    let password = password_url(32);
    values["password"] = serde_json::json!(password);
    values["fallbackDest"] = serde_json::json!(args.fallback_dest);
    format!(
        "listen = {}\n\n[trojan]\npassword = {}\ndest = {}\n",
        q(&args.listen),
        q(&password),
        q(&args.fallback_dest)
    )
}

fn render_hysteria2(
    components: &ComponentSet,
    args: &GenerateMainConfigArgs,
    values: &mut serde_json::Value,
) -> String {
    let password = password_url(24);
    let user_password = password_url(24);
    let obfs_password = password_url(24);
    let obfs = components.hysteria_obfs.unwrap_or(HysteriaObfs::Gecko);
    values["password"] = serde_json::json!(password);
    values["userName"] = serde_json::json!("flclash");
    values["userPassword"] = serde_json::json!(user_password);
    values["obfsPassword"] = serde_json::json!(obfs_password);
    values["obfs"] = serde_json::json!(hysteria_obfs_name(obfs));
    let obfs_table = match obfs {
        HysteriaObfs::Gecko => format!(
            "[hysteria2.obfs]\ntype = \"gecko\"\npassword = {}\nmin_packet_size = 640\nmax_packet_size = 1200\n",
            q(&obfs_password)
        ),
        HysteriaObfs::Salamander => format!(
            "[hysteria2.obfs]\ntype = \"salamander\"\npassword = {}\n",
            q(&obfs_password)
        ),
    };
    format!(
        "listen = {}\n\n[hysteria2]\npassword = {}\ndown_mbps = 100\nignore_client_bandwidth = false\ndisable_udp = false\n\n[[hysteria2.users]]\nname = \"flclash\"\npassword = {}\nemail = {}\n\n{}",
        q(&args.listen),
        q(&password),
        q(&user_password),
        q(&args.email),
        obfs_table
    )
}

fn render_tuic(args: &GenerateMainConfigArgs, values: &mut serde_json::Value) -> String {
    let uuid = uuid_v4();
    let password = password_url(24);
    values["uuid"] = serde_json::json!(uuid);
    values["password"] = serde_json::json!(password);
    values["congestion"] = serde_json::json!(args.tuic_congestion);
    format!(
        "listen = {}\n\n[tuic]\ncongestion_control = {}\nauth_timeout = 3\nzero_rtt_handshake = false\nheartbeat = 10\n\n[[tuic.users]]\nname = \"flclash\"\nemail = {}\nuuid = {}\npassword = {}\n",
        q(&args.listen),
        q(&args.tuic_congestion),
        q(&args.email),
        q(&uuid),
        q(&password)
    )
}

fn render_vmess_inbound(args: &GenerateMainConfigArgs, values: &mut serde_json::Value) -> String {
    let uuid = uuid_v4();
    values["uuid"] = serde_json::json!(uuid);
    format!(
        "listen = {}\n\n[vmess]\n\n[[vmess.users]]\nid = {}\nemail = {}\n",
        q(&args.listen),
        q(&uuid),
        q(&args.email)
    )
}

fn render_naive(args: &GenerateMainConfigArgs, values: &mut serde_json::Value) -> String {
    let username = "alice";
    let password = password_url(24);
    values["username"] = serde_json::json!(username);
    values["password"] = serde_json::json!(password);
    values["fallbackDest"] = serde_json::json!(args.fallback_dest);
    format!(
        "listen = {}\n\n[naive]\npadding_header_name = \"Padding\"\n\n[naive.tls]\ndest = {}\n\n[[naive.users]]\nusername = {}\npassword = {}\nemail = {}\n",
        q(&args.listen),
        q(&args.fallback_dest),
        q(username),
        q(&password),
        q(&args.email)
    )
}

fn q(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization should not fail")
}

fn tokens(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn inbound_name(inbound: Inbound) -> &'static str {
    match inbound {
        Inbound::Vless => "vless",
        Inbound::Shadowsocks2022 => "shadowsocks-2022",
        Inbound::ShadowsocksAead => "shadowsocks-aead",
        Inbound::Trojan => "trojan",
        Inbound::Hysteria2 => "hysteria2",
        Inbound::Tuic => "tuic",
        Inbound::Vmess => "vmess",
        Inbound::Naive => "naive",
    }
}

fn tls_layer_name(layer: TlsLayer) -> &'static str {
    match layer {
        TlsLayer::Reality => "reality",
        TlsLayer::AnyTls => "anytls",
        TlsLayer::Tls => "tls",
    }
}

fn framing_name(framing: Framing) -> &'static str {
    match framing {
        Framing::WebSocket => "websocket",
        Framing::HttpUpgrade => "httpupgrade",
        Framing::Grpc => "grpc",
        Framing::Xhttp => "xhttp",
    }
}

fn hysteria_obfs_name(obfs: HysteriaObfs) -> &'static str {
    match obfs {
        HysteriaObfs::Gecko => "gecko",
        HysteriaObfs::Salamander => "salamander",
    }
}

fn hex(bytes: usize) -> String {
    let mut data = vec![0u8; bytes];
    OsRng.fill_bytes(&mut data);
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn password_url(bytes: usize) -> String {
    let mut data = vec![0u8; bytes];
    OsRng.fill_bytes(&mut data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn psk_for_method(method: &str) -> String {
    let bytes = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" => 32,
        _ => return password_url(24),
    };
    let mut data = vec![0u8; bytes];
    OsRng.fill_bytes(&mut data);
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn uuid_v4() -> String {
    let mut data = [0u8; 16];
    OsRng.fill_bytes(&mut data);
    data[6] = (data[6] & 0x0f) | 0x40;
    data[8] = (data[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        data[0],
        data[1],
        data[2],
        data[3],
        data[4],
        data[5],
        data[6],
        data[7],
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
        data[14],
        data[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SUPPORTED_CLUSTERS: &[(&str, &str)] = &[
        ("reality-vision", "reality-vision"),
        ("anytls-vision", "anytls-vision"),
        ("tls-vision", "tls-vision"),
        ("ws-tcp", "ws-tcp"),
        ("httpupgrade", "httpupgrade"),
        ("grpc", "grpc"),
        ("xhttp", "xhttp"),
        ("vless-raw", "vless-raw"),
        ("hysteria2-gecko", "hysteria2-gecko"),
        ("hysteria2-salamander", "hysteria2-salamander"),
        ("tuic", "tuic"),
        ("trojan-tls", "trojan-tls"),
        ("shadowsocks-2022", "shadowsocks-2022"),
        ("shadowsocks-aead", "shadowsocks-aead"),
        ("vmess", "vmess"),
        ("naive", "naive"),
    ];

    fn args(cluster: &str) -> GenerateMainConfigArgs {
        GenerateMainConfigArgs {
            cluster: cluster.into(),
            output: None,
            output_dir: None,
            no_manifest: false,
            listen: "0.0.0.0:443".into(),
            email: "user@example.com".into(),
            reality_dest: "www.microsoft.com:443".into(),
            fallback_dest: "127.0.0.1:8080".into(),
            shadowsocks_method: "2022-blake3-aes-128-gcm".into(),
            tuic_congestion: "cubic".into(),
        }
    }

    fn render(cluster: &str) -> RenderedConfig {
        let set = ComponentSet::parse(cluster).expect("cluster should parse");
        render_config(&set, &args(cluster)).expect("cluster should render")
    }

    fn fixture(path: &str) -> String {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .unwrap_or_else(|err| panic!("failed to read fixture {path}: {err}"))
    }

    fn normalized_snapshot_content(rendered: &RenderedConfig) -> String {
        let mut text = rendered.content.clone();
        for (key, placeholder) in [
            ("uuid", "<UUID>"),
            ("privateKey", "<REALITY_PRIVATE_KEY>"),
            ("shortId", "<REALITY_SHORT_ID>"),
            ("password", "<PASSWORD>"),
            ("userPassword", "<USER_PASSWORD>"),
            ("obfsPassword", "<OBFS_PASSWORD>"),
        ] {
            if let Some(value) = rendered.values.get(key).and_then(|item| item.as_str()) {
                text = text.replace(value, placeholder);
            }
        }
        format!("{}\n", text.trim_end_matches('\n'))
    }

    fn value<'a>(rendered: &'a RenderedConfig, key: &str) -> &'a str {
        rendered.values[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing string value {key} for {}", rendered.canonical))
    }

    fn assert_hex_len(text: &str, len: usize) {
        assert_eq!(text.len(), len);
        assert!(
            text.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{text} is not hex"
        );
    }

    fn assert_url_password_bytes(text: &str, expected_len: usize) {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .expect("password should be URL-safe base64 without padding");
        assert_eq!(decoded.len(), expected_len);
    }

    fn assert_standard_b64_bytes(text: &str, expected_len: usize) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text)
            .expect("password should be standard base64");
        assert_eq!(decoded.len(), expected_len);
    }

    fn assert_uuid_v4(text: &str) {
        let uuid = wrongsv_uuid::Uuid::parse_string(text).expect("uuid should parse");
        let bytes = uuid.as_bytes();
        assert_eq!(bytes[6] >> 4, 4, "{text} should be UUIDv4");
        assert_eq!(bytes[8] >> 6, 2, "{text} should use RFC4122 variant");
    }

    #[test]
    fn renders_all_supported_clusters_to_valid_toml() {
        for (cluster, expected_canonical) in SUPPORTED_CLUSTERS {
            let rendered = render(cluster);
            assert_eq!(
                &rendered.canonical, expected_canonical,
                "{cluster} canonical mismatch"
            );
            assert_eq!(
                rendered.filename,
                format!("{expected_canonical}.toml"),
                "{cluster} filename mismatch"
            );
            validate_rendered(&rendered.content)
                .unwrap_or_else(|err| panic!("{cluster} should validate: {err}"));
            toml::from_str::<wrongsv_server::Config>(&rendered.content)
                .unwrap_or_else(|err| panic!("{cluster} TOML should parse: {err}"));
        }
    }

    #[test]
    fn generated_secret_shapes_match_protocol_requirements() {
        let reality = render("reality-vision");
        assert_uuid_v4(value(&reality, "uuid"));
        assert_hex_len(value(&reality, "privateKey"), 64);
        assert_hex_len(value(&reality, "shortId"), 8);

        let anytls = render("anytls-vision");
        assert_uuid_v4(value(&anytls, "uuid"));
        assert_url_password_bytes(value(&anytls, "password"), 32);

        let shadowsocks_2022 = render("shadowsocks-2022");
        assert_standard_b64_bytes(value(&shadowsocks_2022, "password"), 16);

        let shadowsocks_aead = render("shadowsocks-aead");
        assert_url_password_bytes(value(&shadowsocks_aead, "password"), 24);

        let trojan = render("trojan-tls");
        assert_url_password_bytes(value(&trojan, "password"), 32);

        let hysteria2 = render("hysteria2-gecko");
        assert_url_password_bytes(value(&hysteria2, "password"), 24);
        assert_url_password_bytes(value(&hysteria2, "userPassword"), 24);
        assert_url_password_bytes(value(&hysteria2, "obfsPassword"), 24);
        assert_eq!(value(&hysteria2, "obfs"), "gecko");

        let tuic = render("tuic");
        assert_uuid_v4(value(&tuic, "uuid"));
        assert_url_password_bytes(value(&tuic, "password"), 24);

        let vmess = render("vmess");
        assert_uuid_v4(value(&vmess, "uuid"));

        let naive = render("naive");
        assert_eq!(value(&naive, "username"), "alice");
        assert_url_password_bytes(value(&naive, "password"), 24);
    }

    #[test]
    fn generated_main_config_snapshots_match_fixtures() {
        for (cluster, expected_canonical) in SUPPORTED_CLUSTERS {
            let rendered = render(cluster);
            let actual = normalized_snapshot_content(&rendered);
            let expected = fixture(&format!(
                "tests/snapshots/main-configs/{expected_canonical}.toml"
            ));
            assert_eq!(actual, expected, "{cluster} snapshot mismatch");
        }
    }

    #[test]
    fn rejects_anytls_reality_cluster() {
        let err = ComponentSet::parse("anytls-reality").expect_err("cluster should be invalid");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn rejects_multiple_stack_presets() {
        let err = ComponentSet::parse("reality-vision,anytls-vision")
            .expect_err("cluster should be invalid");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn output_dir_can_skip_manifest_file() {
        let dir = std::env::temp_dir().join(format!(
            "wrongsv-no-manifest-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut args = args("anytls-vision");
        args.output_dir = Some(dir.clone());
        args.no_manifest = true;

        run(args).expect("generation without manifest should succeed");

        assert!(dir.join("anytls-vision.toml").exists());
        assert!(dir.join("README.md").exists());
        assert!(!dir.join("manifest.json").exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn renders_valid_anytls_vision_config() {
        let rendered = render("anytls,vision");
        assert_eq!(rendered.canonical, "anytls-vision");
        assert!(rendered.content.contains("[anytls]"));
        validate_rendered(&rendered.content).expect("generated config should validate");
    }

    #[test]
    fn rejects_multi_config_alias() {
        let err = ComponentSet::parse("flclash-stealth").expect_err("cluster should be invalid");
        assert!(err.contains("multiple mutually exclusive configs"));
    }

    #[cfg(unix)]
    #[test]
    fn write_file_restricts_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "wrongsv-main-config-perms-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = dir.join("secret.toml");

        write_file(&path, "password = \"secret\"").expect("secret file should be written");

        let content = std::fs::read_to_string(&path).expect("secret file should be readable");
        assert_eq!(content, "password = \"secret\"\n");
        let mode = std::fs::metadata(&path)
            .expect("secret file metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(dir);
    }
}
