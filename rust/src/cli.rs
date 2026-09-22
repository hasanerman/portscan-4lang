use crate::error::AppError;

const DEFAULT_PORTS: &str = "1-1024";
const DEFAULT_TIMEOUT_MS: u64 = 800;
const DEFAULT_CONCURRENCY: usize = 500;
const MIN_TIMEOUT_MS: u64 = 50;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MIN_CONCURRENCY: usize = 1;
const MAX_CONCURRENCY: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Table,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub target: String,
    pub ports_spec: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub banner: bool,
    pub format: ReportFormat,
    pub confirmed: bool,
    pub help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports_spec: DEFAULT_PORTS.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            concurrency: DEFAULT_CONCURRENCY,
            banner: false,
            format: ReportFormat::Table,
            confirmed: false,
            help: false,
        }
    }
}

pub fn usage() -> &'static str {
    "portscan <target> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>]\n\
     \x20                [--banner] [--format table|json] [--yes-i-own-this] [--help]\n"
}

fn is_value_flag(arg: &str) -> bool {
    matches!(arg, "--ports" | "--timeout" | "--concurrency" | "--format")
}

pub fn parse<I, S>(arguments: I) -> Result<Options, AppError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = Options::default();
    let mut iterator = arguments.into_iter();

    while let Some(raw) = iterator.next() {
        let argument = raw.as_ref();

        match argument {
            "--help" | "-h" => {
                options.help = true;
                return Ok(options);
            }
            "--banner" => {
                options.banner = true;
                continue;
            }
            "--yes-i-own-this" => {
                options.confirmed = true;
                continue;
            }
            _ if is_value_flag(argument) => {}
            _ if argument.starts_with("--") => {
                return Err(AppError(format!("unknown argument: {argument}")));
            }
            _ => {
                if !options.target.is_empty() {
                    return Err(AppError("only one target is allowed".to_string()));
                }
                options.target = argument.to_string();
                continue;
            }
        }

        let value = iterator
            .next()
            .ok_or_else(|| AppError(format!("{argument} is missing a value")))?;
        let value = value.as_ref();

        match argument {
            "--ports" => options.ports_spec = value.to_string(),
            "--format" => {
                options.format = match value {
                    "table" => ReportFormat::Table,
                    "json" => ReportFormat::Json,
                    _ => return Err(AppError("format must be table or json".to_string())),
                };
            }
            "--timeout" => {
                let number: u64 = value
                    .parse()
                    .map_err(|_| AppError(format!("a number was expected: {value}")))?;
                if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&number) {
                    return Err(AppError(
                        "timeout must be between 50 and 60000 ms".to_string(),
                    ));
                }
                options.timeout_ms = number;
            }
            "--concurrency" => {
                let number: usize = value
                    .parse()
                    .map_err(|_| AppError(format!("a number was expected: {value}")))?;
                if !(MIN_CONCURRENCY..=MAX_CONCURRENCY).contains(&number) {
                    return Err(AppError(
                        "concurrency must be between 1 and 10000".to_string(),
                    ));
                }
                options.concurrency = number;
            }
            _ => unreachable!(),
        }
    }

    if options.target.is_empty() {
        return Err(AppError("a target is required".to_string()));
    }
    Ok(options)
}
