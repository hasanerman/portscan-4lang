use std::fmt::Write as _;

use crate::scanner::{PortResult, PortState};

const TABLE_WIDTH: usize = 56;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanCounts {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub errors: usize,
}

pub struct ScanReport<'a> {
    pub target: &'a str,
    pub address: &'a str,
    pub results: &'a [PortResult],
    pub elapsed_ms: u64,
}

pub fn count_results(results: &[PortResult]) -> ScanCounts {
    let mut counts = ScanCounts::default();

    for item in results {
        match item.state {
            PortState::Open => counts.open += 1,
            PortState::Closed => counts.closed += 1,
            PortState::Filtered => counts.filtered += 1,
            PortState::Error => counts.errors += 1,
        }
    }
    counts
}

pub fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for byte in text.bytes() {
        if byte == b'"' || byte == b'\\' {
            out.push('\\');
            out.push(byte as char);
        } else if byte < 0x20 {
            let _ = write!(out, "\\u{byte:04x}");
        } else {
            out.push(byte as char);
        }
    }
    out.push('"');
}

pub fn write_table(report: &ScanReport) -> String {
    let counts = count_results(report.results);
    let mut out = String::new();

    let _ = writeln!(out, "{:<7} {:<9} {:>6}  BANNER", "PORT", "STATE", "MS");
    out.push_str(&"-".repeat(TABLE_WIDTH));
    out.push('\n');

    for item in report.results {
        if item.state == PortState::Open {
            let _ = writeln!(
                out,
                "{:<7} {:<9} {:>6}  {}",
                item.port,
                item.state.name(),
                item.ms,
                item.banner
            );
        }
    }

    let _ = write!(
        out,
        "\nscanned {} ports on {} ({}) in {} ms: {} open, {} closed, {} filtered",
        report.results.len(),
        report.target,
        report.address,
        report.elapsed_ms,
        counts.open,
        counts.closed,
        counts.filtered
    );
    if counts.errors > 0 {
        let _ = write!(out, ", {} errors", counts.errors);
    }
    out.push('\n');
    out
}

pub fn write_json(report: &ScanReport) -> String {
    let counts = count_results(report.results);
    let mut out = String::new();

    out.push_str("{\"target\":");
    write_json_string(&mut out, report.target);
    out.push_str(",\"address\":");
    write_json_string(&mut out, report.address);
    let _ = write!(out, ",\"scanned\":{},\"open\":[", report.results.len());

    let mut first = true;
    for item in report.results {
        if item.state != PortState::Open {
            continue;
        }
        if !first {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"port\":{},\"state\":\"{}\",\"banner\":",
            item.port,
            item.state.name()
        );
        write_json_string(&mut out, &item.banner);
        let _ = write!(out, ",\"ms\":{}}}", item.ms);
        first = false;
    }

    let _ = write!(
        out,
        "],\"closed\":{},\"filtered\":{},\"errors\":{},\"elapsed_ms\":{}}}",
        counts.closed, counts.filtered, counts.errors, report.elapsed_ms
    );
    out.push('\n');
    out
}
