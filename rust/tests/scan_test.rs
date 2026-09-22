use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use portscan::cli::{self, ReportFormat};
use portscan::local::is_local;
use portscan::ports;
use portscan::report::{write_json, write_table, ScanReport};
use portscan::scanner::{self, is_http_port, sanitize_banner, PortResult, PortState, ScanConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn parse_ports(spec: &str) -> Result<Vec<u16>, ()> {
    ports::parse(spec).map_err(|_| ())
}

#[test]
fn accepts_valid_specs() {
    assert_eq!(parse_ports("22").unwrap(), vec![22]);
    assert_eq!(parse_ports("1-10").unwrap(), (1..=10).collect::<Vec<_>>());
    assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
    assert_eq!(parse_ports("80,22,80").unwrap(), vec![22, 80]);
    assert_eq!(parse_ports("1-3,2-5").unwrap().len(), 5);
    assert_eq!(parse_ports("65535").unwrap(), vec![65535]);
    assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
}

#[test]
fn rejects_invalid_specs() {
    for spec in [
        "",
        "0",
        "65536",
        "70000",
        "100-1",
        "1-",
        "-5",
        "a",
        "22,,80",
        "22,",
        ",22",
        "1-2-3",
        "-",
        "12x",
        " 22",
        "99999999999999999999",
    ] {
        assert!(parse_ports(spec).is_err(), "should reject: {spec}");
    }
}

#[test]
fn args_defaults_and_flags() {
    let defaults = cli::parse(["127.0.0.1"]).unwrap();
    assert_eq!(defaults.target, "127.0.0.1");
    assert_eq!(defaults.ports_spec, "1-1024");
    assert_eq!(defaults.timeout_ms, 800);
    assert_eq!(defaults.concurrency, 500);
    assert!(!defaults.banner && !defaults.confirmed);
    assert_eq!(defaults.format, ReportFormat::Table);

    let full = cli::parse([
        "localhost",
        "--ports",
        "22,80",
        "--timeout",
        "250",
        "--concurrency",
        "64",
        "--banner",
        "--format",
        "json",
        "--yes-i-own-this",
    ])
    .unwrap();
    assert_eq!(full.target, "localhost");
    assert_eq!(full.ports_spec, "22,80");
    assert_eq!(full.timeout_ms, 250);
    assert_eq!(full.concurrency, 64);
    assert!(full.banner && full.confirmed);
    assert_eq!(full.format, ReportFormat::Json);
}

#[test]
fn args_rejects_bad_input() {
    let empty: [&str; 0] = [];
    assert!(cli::parse(empty).is_err());
    assert!(cli::parse(["a", "b"]).is_err());
    assert!(cli::parse(["a", "--zoom"]).is_err());
    assert!(cli::parse(["a", "--ports"]).is_err());
    assert!(cli::parse(["a", "--timeout", "10"]).is_err());
    assert!(cli::parse(["a", "--concurrency", "0"]).is_err());
    assert!(cli::parse(["a", "--timeout", "abc"]).is_err());
    assert!(cli::parse(["a", "--format", "xml"]).is_err());
    assert!(cli::parse(["--help"]).unwrap().help);
}

#[test]
fn local_address_detection() {
    let local_cases = [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:10.0.0.1",
    ];
    for text in local_cases {
        let address: IpAddr = text.parse().unwrap();
        assert!(is_local(address), "expected local: {text}");
    }

    let remote_cases = [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "172.15.0.1",
        "192.169.0.1",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",
    ];
    for text in remote_cases {
        let address: IpAddr = text.parse().unwrap();
        assert!(!is_local(address), "expected non-local: {text}");
    }
}

#[test]
fn sanitize_banner_behaviour() {
    assert_eq!(
        sanitize_banner(b"SSH-2.0-OpenSSH_9.6\r\nextra"),
        "SSH-2.0-OpenSSH_9.6"
    );
    assert_eq!(sanitize_banner(&[b'A', 0x01, b'B', 0xff, b'C']), "A.B.C");
    assert_eq!(sanitize_banner(b"\r\n  220 hello  \r\n"), "220 hello");
    let longer = vec![b'x'; 300];
    assert_eq!(sanitize_banner(&longer).chars().count(), 120);
    assert_eq!(sanitize_banner(b""), "");
}

#[test]
fn http_ports_are_recognised() {
    assert!(is_http_port(80) && is_http_port(8080) && is_http_port(8000) && is_http_port(8888));
    assert!(!is_http_port(22) && !is_http_port(443));
}

async fn open_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn make_config(banner: bool) -> ScanConfig {
    ScanConfig {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        timeout: Duration::from_millis(2000),
        banner,
    }
}

#[tokio::test]
async fn open_and_closed_ports_are_detected() {
    let (listener, port) = open_listener().await;
    let config = make_config(false);

    let open_result = scanner::scan_port(config, port).await;
    assert_eq!(open_result.state, PortState::Open);

    drop(listener);
    let closed_result = scanner::scan_port(config, port).await;
    assert_eq!(closed_result.state, PortState::Closed);
}

#[tokio::test]
async fn banner_grab_reads_server_text() {
    let (listener, port) = open_listener().await;
    let config = make_config(true);

    let server = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"220 izci test ready\r\n").await;
            let mut sink = [0u8; 16];
            let _ = tokio::time::timeout(Duration::from_millis(500), socket.read(&mut sink)).await;
        }
    });

    let result = scanner::scan_port(config, port).await;
    server.await.unwrap();

    assert_eq!(result.state, PortState::Open);
    assert_eq!(result.banner, "220 izci test ready");
}

#[tokio::test]
async fn repeated_scans_are_stable() {
    const RANGE_SIZE: u16 = 200;
    const ROUNDS: usize = 20;

    let (listener, port) = open_listener().await;
    let config = make_config(false);
    let first = port - RANGE_SIZE / 2;
    let port_list: Vec<u16> = (first..first + RANGE_SIZE).collect();

    let listener_index = (port - first) as usize;

    // Only the port this test owns is asserted on. The rest of the window sits
    // in the OS ephemeral range, where unrelated processes - including the other
    // tests in this file, which cargo runs in parallel - claim and release ports
    // while the scan runs. What repetition proves here is that our own scanner
    // keeps returning a complete, correctly ordered result set and never loses
    // the one port we control, which is what a socket leak would break.
    for _ in 0..=ROUNDS {
        let current = scanner::scan_ports(config, &port_list, 64).await;

        assert_eq!(current.len(), port_list.len());
        for (expected, result) in port_list.iter().zip(current.iter()) {
            assert_eq!(*expected, result.port);
        }
        assert_eq!(current[listener_index].state, PortState::Open);
    }
    drop(listener);
}

fn make_result(port: u16, state: PortState, ms: u64, banner: &str) -> PortResult {
    PortResult {
        port,
        state,
        ms,
        banner: banner.to_string(),
    }
}

#[test]
fn json_report_matches_expected_layout() {
    let items = vec![
        make_result(22, PortState::Open, 2, "SSH-2.0-test"),
        make_result(23, PortState::Closed, 0, ""),
        make_result(24, PortState::Filtered, 800, ""),
    ];
    let report = ScanReport {
        target: "host",
        address: "127.0.0.1",
        results: &items,
        elapsed_ms: 9,
    };

    let text = write_json(&report);
    assert_eq!(
        text,
        "{\"target\":\"host\",\"address\":\"127.0.0.1\",\"scanned\":3,\"open\":[{\"port\":22,\"state\":\"open\",\"banner\":\"SSH-2.0-test\",\"ms\":2}],\"closed\":1,\"filtered\":1,\"errors\":0,\"elapsed_ms\":9}\n"
    );
}

#[test]
fn json_report_escapes_banner() {
    let items = vec![make_result(80, PortState::Open, 1, "say \"hi\" \\ done")];
    let report = ScanReport {
        target: "t",
        address: "127.0.0.1",
        results: &items,
        elapsed_ms: 1,
    };

    let text = write_json(&report);
    assert!(text.contains("\"banner\":\"say \\\"hi\\\" \\\\ done\""));
}

#[test]
fn table_report_lists_only_open_ports() {
    let items = vec![
        make_result(22, PortState::Open, 3, "SSH-2.0-test"),
        make_result(23, PortState::Closed, 0, ""),
    ];
    let report = ScanReport {
        target: "host",
        address: "127.0.0.1",
        results: &items,
        elapsed_ms: 5,
    };

    let text = write_table(&report);
    assert!(text.contains("SSH-2.0-test"));
    assert!(text.contains("scanned 2 ports on host (127.0.0.1) in 5 ms: 1 open, 1 closed, 0 filtered"));
    assert!(!text.contains("closed  "));
}
