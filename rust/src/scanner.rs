use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Socket, Type};
use tokio::sync::Semaphore;

const BANNER_MAX_CHARS: usize = 120;
const BANNER_READ_BYTES: usize = 1024;
const BANNER_WAIT_MS: u64 = 500;
const HTTP_PROBE: &[u8] = b"HEAD / HTTP/1.0\r\n\r\n";
const PRINTABLE_FIRST: u8 = 0x20;
const PRINTABLE_LAST: u8 = 0x7e;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Error,
}

impl PortState {
    pub fn name(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub ms: u64,
    pub banner: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    pub address: IpAddr,
    pub timeout: Duration,
    pub banner: bool,
}

pub fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 8000 | 8080 | 8888)
}

pub fn sanitize_banner(data: &[u8]) -> String {
    let trimmed_start = data
        .iter()
        .position(|&b| b != b'\r' && b != b'\n' && b != b' ')
        .unwrap_or(data.len());
    let mut out = String::new();

    for &byte in &data[trimmed_start..] {
        if byte == b'\r' || byte == b'\n' {
            break;
        }
        if out.chars().count() >= BANNER_MAX_CHARS {
            break;
        }
        let ch = if (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(&byte) {
            byte as char
        } else {
            '.'
        };
        out.push(ch);
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

fn classify_error(error: &io::Error) -> PortState {
    use io::ErrorKind;

    match error.kind() {
        ErrorKind::ConnectionRefused => PortState::Closed,
        ErrorKind::TimedOut | ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
            PortState::Filtered
        }
        _ => match error.raw_os_error() {
            Some(code) if is_filtered_os_error(code) => PortState::Filtered,
            Some(code) if is_refused_os_error(code) => PortState::Closed,
            _ => PortState::Error,
        },
    }
}

#[cfg(windows)]
fn is_refused_os_error(code: i32) -> bool {
    const WSAECONNREFUSED: i32 = 10061;
    code == WSAECONNREFUSED
}

#[cfg(not(windows))]
fn is_refused_os_error(code: i32) -> bool {
    code == libc::ECONNREFUSED
}

#[cfg(windows)]
fn is_filtered_os_error(code: i32) -> bool {
    const WSAETIMEDOUT: i32 = 10060;
    const WSAEHOSTUNREACH: i32 = 10065;
    const WSAENETUNREACH: i32 = 10051;
    const WSAEHOSTDOWN: i32 = 10064;
    const WSAEACCES: i32 = 10013;
    matches!(
        code,
        WSAETIMEDOUT | WSAEHOSTUNREACH | WSAENETUNREACH | WSAEHOSTDOWN | WSAEACCES
    )
}

#[cfg(not(windows))]
fn is_filtered_os_error(code: i32) -> bool {
    matches!(
        code,
        libc::ETIMEDOUT | libc::EHOSTUNREACH | libc::ENETUNREACH | libc::EHOSTDOWN | libc::EACCES | libc::EPERM
    )
}

// Windows keeps retrying a SYN for its default RTO backoff (roughly two
// seconds) even against a refused loopback port, and tokio's async connect
// waits on that same signal. Disabling SYN retransmission makes a refused
// connection fail after the very first round trip, matching the C and C++
// implementations. This has no effect on Unix, where the OS reports
// ECONNREFUSED immediately.
#[cfg(windows)]
fn disable_syn_retransmission(socket: &Socket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_TCP_INITIAL_RTO, SOCKET};

    #[repr(C)]
    struct TcpInitialRtoParameters {
        rtt: u16,
        max_syn_retransmissions: u8,
    }

    // mstcpip.h: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS is ((UCHAR)-2), i.e. 0xFE.
    // 0xFF is TCP_INITIAL_RTO_UNSPECIFIED_MAX_SYN_RETRANSMISSIONS, which leaves
    // the system default (and its ~2s refusal delay) untouched.
    const NO_SYN_RETRANSMISSIONS: u8 = 0xfe;
    const UNSPECIFIED_RTT: u16 = 0xffff;

    let parameters = TcpInitialRtoParameters {
        rtt: UNSPECIFIED_RTT,
        max_syn_retransmissions: NO_SYN_RETRANSMISSIONS,
    };
    let mut returned: u32 = 0;

    unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_TCP_INITIAL_RTO,
            &parameters as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TcpInitialRtoParameters>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

// The actual TCP work happens synchronously on a blocking-pool thread using
// a plain nonblocking connect plus poll, exactly like the C and C++
// versions. tokio's own async connect (via mio's Windows AFD/IOCP backend)
// does not reliably surface an immediate SIO_TCP_INITIAL_RTO failure, so it
// is not used here; see edu.md for the measurements behind this choice.
fn blocking_scan(config: ScanConfig, port: u16) -> PortResult {
    let start = Instant::now();
    let target = SocketAddr::new(config.address, port);
    let domain = if target.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };

    let outcome = Socket::new(domain, Type::STREAM, None).and_then(|socket| {
        #[cfg(windows)]
        disable_syn_retransmission(&socket);
        socket.connect_timeout(&target.into(), config.timeout)?;
        Ok(socket)
    });

    let ms = start.elapsed().as_millis() as u64;

    let socket = match outcome {
        Ok(socket) => socket,
        Err(error) => {
            let state = if error.kind() == io::ErrorKind::TimedOut {
                PortState::Filtered
            } else {
                classify_error(&error)
            };
            return PortResult {
                port,
                state,
                ms,
                banner: String::new(),
            };
        }
    };

    let banner = if config.banner {
        read_banner_blocking(&socket, port, config.timeout)
    } else {
        String::new()
    };

    PortResult {
        port,
        state: PortState::Open,
        ms,
        banner,
    }
}

fn read_banner_blocking(socket: &Socket, port: u16, timeout: Duration) -> String {
    let wait = timeout.min(Duration::from_millis(BANNER_WAIT_MS));
    let mut stream: std::net::TcpStream = match socket.try_clone() {
        Ok(clone) => clone.into(),
        Err(_) => return String::new(),
    };

    if stream.set_read_timeout(Some(wait)).is_err() {
        return String::new();
    }
    if is_http_port(port) && stream.write_all(HTTP_PROBE).is_err() {
        return String::new();
    }

    let mut buffer = [0u8; BANNER_READ_BYTES];
    match stream.read(&mut buffer) {
        Ok(count) if count > 0 => sanitize_banner(&buffer[..count]),
        _ => String::new(),
    }
}

pub async fn scan_port(config: ScanConfig, port: u16) -> PortResult {
    tokio::task::spawn_blocking(move || blocking_scan(config, port))
        .await
        .expect("scan task panicked")
}

pub async fn scan_ports(config: ScanConfig, ports: &[u16], concurrency: usize) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = Vec::with_capacity(ports.len());

    for &port in ports {
        let permit = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let _permit = permit.acquire_owned().await.expect("semaphore closed");
            scan_port(config, port).await
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        results.push(task.await.expect("scan task panicked"));
    }
    results
}
