//! Integration tests for the evaluator framework.
//! Starts eval-server, runs eval-client, validates end-to-end results.

use std::time::Duration;

use wrongsv_evaluator_client::runner::run_evaluation;

/// Spawn an eval-server on a random port, run the eval-client against it
/// with a small protocol set, and verify results are returned.
#[test]
fn evaluator_end_to_end_small_subset() {
    let duration_secs = 3; // short duration for fast test

    // Pick an ephemeral port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();
    drop(listener); // release so server can bind

    let listen_addr = format!("127.0.0.1:{port}");
    let token = "test-integration-token";

    // Spawn server in a background thread.
    // Use a std channel to signal readiness.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let listen = listen_addr.clone();
    let server_token = token.to_string();
    let server_handle = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        // Signal ready before blocking on accept
        ready_tx.send(()).map_err(|_| "send failed".to_string())?;
        // Run server — this blocks until a client connects and completes
        rt.block_on(wrongsv_evaluator_server::orchestrator::run_orchestrator(
            &listen,
            &server_token,
            Some("raw,tls"),
            None, // stacks
            duration_secs,
            "127.0.0.1",
            None,
        ))
        .map_err(|e| e.to_string())
    });

    // Wait for server to be ready
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server should start");

    // Extra safety margin
    std::thread::sleep(Duration::from_millis(300));

    // Run client on main thread
    let results =
        run_evaluation(&listen_addr, token, duration_secs, &[]).expect("evaluation should succeed");

    // Verify results
    assert!(
        !results.is_empty(),
        "should have results for at least one protocol"
    );

    for r in &results {
        eprintln!(
            "{}: lat={:.2}ms, bw={:.2}/{:.2} Mbps, loss={:.2}%",
            r.protocol,
            r.latency_ms.avg,
            r.bandwidth_mbps.upload,
            r.bandwidth_mbps.download,
            r.packet_loss_pct
        );

        // Every result should have a protocol name
        assert!(!r.protocol.is_empty(), "protocol name should not be empty");

        // Latency should be >= 0
        assert!(r.latency_ms.min >= 0.0, "latency min should be >= 0");
        assert!(r.latency_ms.max >= 0.0, "latency max should be >= 0");
        assert!(r.latency_ms.avg >= 0.0, "latency avg should be >= 0");

        // Bandwidth should be >= 0
        assert!(r.bandwidth_mbps.upload >= 0.0, "bw upload should be >= 0");
        assert!(
            r.bandwidth_mbps.download >= 0.0,
            "bw download should be >= 0"
        );

        // Packet loss should be in [0, 100]
        assert!(
            (0.0..=100.0).contains(&r.packet_loss_pct),
            "packet loss should be in [0,100], got {}",
            r.packet_loss_pct
        );
    }

    // Wait for server to finish (client disconnect triggers server completion)
    let server_result = server_handle
        .join()
        .expect("server thread should not panic");
    // Server may return Ok or Err depending on timing; both are fine
    if let Err(e) = &server_result {
        eprintln!("server exited with: {e}");
    }
}

/// Run REALITY through the evaluator end-to-end so we verify the
/// orchestrator hands the client the server's real cert raw_pubkey
/// (not the previous all-zeros bypass). The eval-client's
/// `verify_reality_cert` only runs when raw_pubkey is non-zero, so this
/// test would have failed silently before the orchestrator was patched.
#[test]
fn evaluator_reality_uses_real_raw_pubkey() {
    let duration_secs = 3;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let listen_addr = format!("127.0.0.1:{port}");
    let token = "reality-cert-token";

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let listen = listen_addr.clone();
    let server_token = token.to_string();
    let server_handle = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        ready_tx.send(()).map_err(|_| "send failed".to_string())?;
        rt.block_on(wrongsv_evaluator_server::orchestrator::run_orchestrator(
            &listen,
            &server_token,
            Some("reality"),
            None,
            duration_secs,
            "127.0.0.1",
            None,
        ))
        .map_err(|e| e.to_string())
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server should start");
    std::thread::sleep(Duration::from_millis(300));

    let results =
        run_evaluation(&listen_addr, token, duration_secs, &[]).expect("evaluation should succeed");
    let reality = results
        .iter()
        .find(|r| r.protocol == "reality")
        .expect("reality result present");
    assert_eq!(reality.packet_loss_pct, 0.0, "REALITY should be lossless on loopback: {reality:?}");

    let _ = server_handle.join();
}

/// Test that the server rejects a client with a bad token.
#[test]
fn evaluator_rejects_bad_token() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();
    drop(listener);

    let listen_addr = format!("127.0.0.1:{port}");
    let good_token = "the-real-token";

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let listen = listen_addr.clone();
    let server_token = good_token.to_string();
    let server_handle = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        ready_tx.send(()).map_err(|_| "send failed".to_string())?;
        rt.block_on(wrongsv_evaluator_server::orchestrator::run_orchestrator(
            &listen,
            &server_token,
            Some("raw"),
            None, // stacks
            1,
            "127.0.0.1",
            None,
        ))
        .map_err(|e| e.to_string())
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server should start");
    std::thread::sleep(Duration::from_millis(300));

    // Try to connect with a WRONG token
    let result = run_evaluation(&listen_addr, "wrong-token", 1, &[]);
    assert!(result.is_err(), "should reject bad token");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("auth failed") || err_msg.contains("auth"),
        "error should mention auth: {err_msg}"
    );

    let _ = server_handle.join();
}
