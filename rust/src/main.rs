use std::net::{IpAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use portscan::cli::{self, Options, ReportFormat};
use portscan::error::{AppError, EXIT_OK, EXIT_UNRESOLVED, EXIT_USAGE};
use portscan::local::is_local;
use portscan::ports;
use portscan::report::{self, ScanReport};
use portscan::scanner::{self, ScanConfig};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    let options = match cli::parse(&arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}\n{}", cli::usage());
            return ExitCode::from(EXIT_USAGE as u8);
        }
    };

    if options.help {
        print!("{}", cli::usage());
        return ExitCode::from(EXIT_OK as u8);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(options.concurrency.max(1))
        .build()
        .expect("failed to start async runtime");

    match runtime.block_on(run(&options)) {
        Ok(()) => ExitCode::from(EXIT_OK as u8),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.1 as u8)
        }
    }
}

struct ExitError(AppError, i32);

impl std::fmt::Display for ExitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "error: {}", self.0)
    }
}

fn resolve(target: &str) -> Result<IpAddr, ExitError> {
    if let Ok(address) = target.parse::<IpAddr>() {
        return Ok(address);
    }
    let candidate = format!("{target}:0");
    candidate
        .to_socket_addrs()
        .ok()
        .and_then(|mut list| list.next())
        .map(|socket| socket.ip())
        .ok_or_else(|| {
            ExitError(
                AppError(format!("cannot resolve {target}")),
                EXIT_UNRESOLVED,
            )
        })
}

async fn run(options: &Options) -> Result<(), ExitError> {
    let port_list = ports::parse(&options.ports_spec).map_err(|error| ExitError(error, EXIT_USAGE))?;
    let address = resolve(&options.target)?;

    if !is_local(address) {
        if options.confirmed {
            eprintln!("note: scanning a non-local target");
        } else {
            return Err(ExitError(
                AppError(format!(
                    "{} is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it",
                    options.target
                )),
                EXIT_USAGE,
            ));
        }
    }

    let config = ScanConfig {
        address,
        timeout: Duration::from_millis(options.timeout_ms),
        banner: options.banner,
    };

    let start = Instant::now();
    let results = scanner::scan_ports(config, &port_list, options.concurrency).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let report = ScanReport {
        target: &options.target,
        address: &address.to_string(),
        results: &results,
        elapsed_ms,
    };

    let text = match options.format {
        ReportFormat::Json => report::write_json(&report),
        ReportFormat::Table => report::write_table(&report),
    };
    print!("{text}");
    Ok(())
}
