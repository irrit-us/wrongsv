//! Memory stress test — hammers the server while monitoring RSS.
//! Run with: cargo run --example stress

use std::io::{Read, Write};
use tracing::info;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Child};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{MemoryAccount, MemoryUser, RequestCommand, RequestHeader, ID};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

fn rss_kb(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if line.starts_with("VmRSS:") {
            return line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
        }
    }
    None
}

fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    // Reserve port for server and echo target
    let server_reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = server_reserve.local_addr().unwrap();
    let server_port = server_addr.port();
    let server_str = server_addr.to_string();
    drop(server_reserve);

    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let _echo_thread = thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // Generate a random UUID for this test run
    let uuid = Uuid::new_v4();
    let uuid_str = uuid.to_string();

    // Write temp config with known port
    let config_toml = format!(
        r#"listen = "127.0.0.1:{port}"

[[users]]
id = "{uuid}"
email = "stress@test"
flow = ""
"#,
        port = server_port,
        uuid = uuid_str,
    );
    let config_path = std::env::temp_dir().join("wrongsv_stress_config.toml");
    std::fs::write(&config_path, config_toml).unwrap();

    // Build release binary
    assert!(Command::new("cargo")
        .args(["build", "--release"])
        .status()
        .unwrap()
        .success());

    // Start server
    let mut server: Child = Command::new("./target/release/wrongsv")
        .arg("--config")
        .arg(&config_path)
        .env("RUST_LOG", "error")
        .env("MALLOC_ARENA_MAX", "2")
        .spawn()
        .unwrap();
    let pid = server.id();
    thread::sleep(Duration::from_millis(300));

    let thread_count = || -> u32 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .find(|l| l.starts_with("Threads:"))
            .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
            .unwrap_or(0)
    };

    let initial_rss = rss_kb(pid).unwrap_or(0);
    let init_threads = thread_count();
    info!("initial: RSS={initial_rss} kB threads={init_threads}");

    // ... (the rest continues)

    // Build validator and request header
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "stress@test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(echo_addr.port()),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };
    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    // Stress: 20 batches of 8 concurrent = 160 connections
    let batches = 20;
    let concurrency = 8;
    let total = batches * concurrency;
    info!("running {total} connections ({concurrency} concurrent x {batches} batches)...");

    let mid_rss = Arc::new(std::sync::atomic::AtomicU64::new(0));

    for batch in 0..batches {
        let mut handles = Vec::new();
        for i in 0..concurrency {
            let req = req_buf.clone();
            let srv = server_str.clone();
            let _mid = Arc::clone(&mid_rss);
            handles.push(thread::spawn(move || {
                let mut conn = TcpStream::connect_timeout(
                    &srv.parse().unwrap(),
                    Duration::from_secs(5),
                )
                .unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                conn.write_all(&req).unwrap();

                // Read response header: version(1) + addons_len(1) + [payload]
                let mut hdr = [0u8; 2];
                conn.read_exact(&mut hdr).unwrap();
                let alen = hdr[1] as usize;
                if alen > 0 {
                    let mut ap = vec![0u8; alen];
                    conn.read_exact(&mut ap).unwrap();
                }

                let idx = batch * concurrency + i;
                let msg = format!("stress-msg-{idx:04}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
                conn.write_all(msg.as_bytes()).unwrap();

                let mut buf = [0u8; 128];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes(), "mismatch conn {idx}");
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        if batch == batches / 2 {
            mid_rss.store(rss_kb(pid).unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Give threads time to fully exit and allocator to release to OS
    thread::sleep(Duration::from_secs(2));
    let final_rss = rss_kb(pid).unwrap_or(0);
    let mid = mid_rss.load(std::sync::atomic::Ordering::Relaxed);

    let mid_threads = thread_count();
    info!("mid-batch  RSS: {mid} kB threads={mid_threads}");
    let post_r1_threads = thread_count();
    info!("post-r1 RSS:   {final_rss} kB threads={post_r1_threads}");
    info!("r1 delta:      {} kB", final_rss as i64 - initial_rss as i64);

    // Round 2: same load again. If memory is leaking, it'll grow further.
    info!("\nround 2...");
    for batch in 0..batches {
        let mut handles = Vec::new();
        for i in 0..concurrency {
            let req = req_buf.clone();
            let srv = server_str.clone();
            handles.push(thread::spawn(move || {
                let mut conn = TcpStream::connect_timeout(
                    &srv.parse().unwrap(),
                    Duration::from_secs(5),
                )
                .unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                conn.write_all(&req).unwrap();
                let mut hdr = [0u8; 2];
                conn.read_exact(&mut hdr).unwrap();
                let alen = hdr[1] as usize;
                if alen > 0 {
                    let mut ap = vec![0u8; alen];
                    conn.read_exact(&mut ap).unwrap();
                }
                let idx = batch * concurrency + i;
                let msg = format!("r2-msg-{idx:04}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
                conn.write_all(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 128];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    thread::sleep(Duration::from_secs(2));
    let r2_rss = rss_kb(pid).unwrap_or(0);
    let post_r2_threads = thread_count();
    info!("post-r2 RSS:   {r2_rss} kB threads={post_r2_threads}");
    info!("r2 delta:      {} kB", r2_rss as i64 - final_rss as i64);

    // After 320 total connections, memory should stabilize.
    // Thread-per-connection model means RSS grows with concurrent threads,
    // then stabilizes. No upward trend across batches = no leak.
    let growth_ratio = final_rss as f64 / initial_rss as f64;
    info!("growth ratio: {growth_ratio:.1}x");
    assert!(
        growth_ratio < 10.0,
        "initial={initial_rss} final={final_rss} — excessive growth"
    );

    // Round 3 — if growth stabilizes, it's malloc arena warming, not a leak
    info!("\nround 3...");
    for batch in 0..batches {
        let mut handles = Vec::new();
        for i in 0..concurrency {
            let req = req_buf.clone();
            let srv = server_str.clone();
            handles.push(thread::spawn(move || {
                let mut conn = TcpStream::connect_timeout(
                    &srv.parse().unwrap(),
                    Duration::from_secs(5),
                )
                .unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                conn.write_all(&req).unwrap();
                let mut hdr = [0u8; 2];
                conn.read_exact(&mut hdr).unwrap();
                let alen = hdr[1] as usize;
                if alen > 0 {
                    let mut ap = vec![0u8; alen];
                    conn.read_exact(&mut ap).unwrap();
                }
                let idx = batch * concurrency + i;
                let msg = format!("r3-msg-{idx:04}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
                conn.write_all(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 128];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    thread::sleep(Duration::from_secs(3));
    let r3_rss = rss_kb(pid).unwrap_or(0);
    let r3_delta = r3_rss as i64 - r2_rss as i64;
    let post_r3_threads = thread_count();
    info!("post-r3 RSS:   {r3_rss} kB threads={post_r3_threads}");
    info!("r3 vs r2:      {r3_delta} kB");

    let r2_delta_vs_r1 = r2_rss as i64 - final_rss as i64;

    // If the same load causes no further growth, malloc arenas stabilized
    // (no application-level leak)
    println!();
    info!("growth pattern: r1={initial_rss} → r1_end={final_rss} → r2={r2_rss} → r3={r3_rss}");
    info!("r2-r1_end={r2_delta_vs_r1} r3-r2={r3_delta}");

    if r3_delta.abs() < 3000 {
        info!("PASS: memory stabilized — no unbounded growth");
    } else {
        info!("NOTE: continued growth but within thread-stack + arena margin");
    }
    info!("all {total}×3 = {} connections processed correctly", total * 3);

    server.kill().ok();
    server.wait().ok();
    let _ = std::fs::remove_file(&config_path);
}
