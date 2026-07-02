//! `log-stats` — analyze Apache/Nginx web access logs.
//!
//! Thin CLI shell over the [`log_stats`] library: it reads lines (from files or
//! stdin), parses them, optionally filters by status / time, and prints a
//! human-readable report or JSON.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Serialize;

use log_stats::parser::{detect_format, parse_line, Entry, LogFormat, ParseOutcome};
use log_stats::stats::{
    aggregate, group_by_capture, largest_responses, Counted, Report, SizedRequest,
};
use log_stats::{parse_time_bound, TimeFilter};

/// Analyze Apache/Nginx access logs and report statistics.
#[derive(Parser, Debug)]
#[command(
    name = "log-stats",
    version,
    about = "Analyze Apache/Nginx web access logs",
    long_about = None
)]
struct Cli {
    /// Log file(s) to analyze. Reads stdin when none are given (or when `-`).
    files: Vec<PathBuf>,

    /// Number of items to show in each "top" list.
    #[arg(long, default_value_t = 10, value_name = "N")]
    top: usize,

    /// Emit machine-readable JSON instead of a text report.
    #[arg(long)]
    json: bool,

    /// Only include requests with this exact HTTP status code.
    #[arg(long, value_name = "CODE")]
    status: Option<u16>,

    /// Only include requests at/after this time (inclusive).
    ///
    /// Accepts CLF (`10/Oct/2000:13:55:36 -0700`), ISO-8601, `YYYY-MM-DD HH:MM:SS`,
    /// or `YYYY-MM-DD`.
    #[arg(long, value_name = "TIME")]
    since: Option<String>,

    /// Only include requests before this time (exclusive).
    #[arg(long, value_name = "TIME")]
    until: Option<String>,

    /// Log dialect. `auto` detects from the first lines.
    #[arg(long, value_name = "FMT", default_value = "auto")]
    format: String,

    /// Generic mode: report the frequency of capture group 1 of this regex
    /// across all input lines (works on ANY log, not just access logs).
    #[arg(long, value_name = "REGEX")]
    group: Option<String>,

    /// Also report the `--top` individual requests with the largest response
    /// sizes (by bytes). Adds a section to the text report and a
    /// `largest_responses` array to `--json`.
    #[arg(long)]
    largest: bool,
}

/// Read all input lines from the given files, or stdin when none/`-`.
fn read_lines(files: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();

    let use_stdin = files.is_empty() || (files.len() == 1 && files[0].as_os_str() == "-");

    if use_stdin {
        let stdin = io::stdin();
        let mut buf = String::new();
        stdin
            .lock()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        out.extend(buf.lines().map(|l| l.to_string()));
        return Ok(out);
    }

    for path in files {
        if path.as_os_str() == "-" {
            let mut buf = String::new();
            io::stdin().lock().read_to_string(&mut buf)?;
            out.extend(buf.lines().map(|l| l.to_string()));
            continue;
        }
        let file =
            File::open(path).with_context(|| format!("opening log file {}", path.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            out.push(line.with_context(|| format!("reading {}", path.display()))?);
        }
    }
    Ok(out)
}

/// Wrapper struct for the `--group` JSON output shape.
#[derive(Serialize)]
struct GroupReport {
    pattern: String,
    matched_lines: u64,
    total_lines: u64,
    groups: Vec<Counted>,
}

fn main() {
    if let Err(err) = run() {
        // A closed downstream pipe (e.g. `log-stats ... | head`) surfaces as an
        // I/O BrokenPipe error. That is normal, expected shutdown — exit 0
        // silently instead of printing an error and returning failure.
        for cause in err.chain() {
            if let Some(io_err) = cause.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::BrokenPipe {
                    std::process::exit(0);
                }
            }
        }
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let lines = read_lines(&cli.files)?;

    // --- generic group mode: short-circuits the access-log pipeline ---------
    if let Some(pattern) = &cli.group {
        let re =
            Regex::new(pattern).with_context(|| format!("invalid --group regex: {pattern}"))?;
        let (groups, matched) = group_by_capture(lines.iter().map(|s| s.as_str()), &re, cli.top);
        let report = GroupReport {
            pattern: pattern.clone(),
            matched_lines: matched,
            total_lines: lines.len() as u64,
            groups,
        };
        if cli.json {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &report)?;
            writeln!(stdout)?;
        } else {
            print_group_report(&report)?;
        }
        return Ok(());
    }

    // --- determine format ---------------------------------------------------
    let format = match LogFormat::parse(&cli.format) {
        Some(f) => f,
        None => anyhow::bail!(
            "invalid --format '{}': expected combined, common, or auto",
            cli.format
        ),
    };
    let format = if format == LogFormat::Auto {
        detect_format(lines.iter().map(|s| s.as_str()), 50)
    } else {
        format
    };

    // --- time filter --------------------------------------------------------
    let time_filter = TimeFilter {
        since: cli.since.as_deref().map(parse_time_bound).transpose()?,
        until: cli.until.as_deref().map(parse_time_bound).transpose()?,
    };

    // --- parse + filter -----------------------------------------------------
    let mut entries: Vec<Entry> = Vec::new();
    let mut malformed: u64 = 0;
    let mut blank: u64 = 0;

    for line in &lines {
        match parse_line(line, format) {
            ParseOutcome::Ok(e) => {
                if let Some(code) = cli.status {
                    if e.status != code {
                        continue;
                    }
                }
                if !time_filter.matches(&e) {
                    continue;
                }
                entries.push(e);
            }
            ParseOutcome::Malformed => malformed += 1,
            ParseOutcome::Blank => blank += 1,
        }
    }

    let report = aggregate(&entries, cli.top, malformed, blank);
    let largest = if cli.largest {
        Some(largest_responses(&entries, cli.top))
    } else {
        None
    };

    if cli.json {
        let mut stdout = io::stdout().lock();
        if let Some(largest) = &largest {
            // Splice the extra list into the report object rather than nesting,
            // so the JSON shape is a superset of the default one.
            #[derive(Serialize)]
            struct FullReport<'a> {
                #[serde(flatten)]
                report: &'a Report,
                largest_responses: &'a [SizedRequest],
            }
            serde_json::to_writer_pretty(
                &mut stdout,
                &FullReport {
                    report: &report,
                    largest_responses: largest,
                },
            )?;
        } else {
            serde_json::to_writer_pretty(&mut stdout, &report)?;
        }
        writeln!(stdout)?;
    } else {
        print_report(&report, format, cli.top)?;
        if let Some(largest) = &largest {
            print_largest(largest)?;
        }
    }

    Ok(())
}

/// Render the "Largest responses" section (opt-in via `--largest`).
fn print_largest(items: &[SizedRequest]) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "\nLargest responses (by bytes):")?;
    if items.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }
    let width = items
        .iter()
        .map(|r| r.bytes.to_string().len())
        .max()
        .unwrap_or(1);
    for r in items {
        let method = r.method.as_deref().unwrap_or("-");
        let path = r.path.as_deref().unwrap_or("-");
        writeln!(
            out,
            "  {:>width$}  {:>3} {} {}",
            r.bytes,
            r.status,
            method,
            path,
            width = width
        )?;
    }
    Ok(())
}

/// Render a `Vec<Counted>` as an indented list, or "(none)" when empty.
fn write_counted(out: &mut impl Write, items: &[Counted]) -> io::Result<()> {
    if items.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }
    let width = items
        .iter()
        .map(|c| c.count.to_string().len())
        .max()
        .unwrap_or(1);
    for c in items {
        writeln!(out, "  {:>width$}  {}", c.count, c.key, width = width)?;
    }
    Ok(())
}

/// Render the human-readable access-log report.
fn print_report(r: &Report, format: LogFormat, top: usize) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let fmt_name = match format {
        LogFormat::Combined => "combined",
        LogFormat::Common => "common",
        LogFormat::Auto => "auto",
    };

    writeln!(out, "log-stats report  (format: {fmt_name}, top {top})")?;
    writeln!(out, "{}", "=".repeat(52))?;
    writeln!(out, "Total requests : {}", r.total_requests)?;
    writeln!(out, "Unique IPs     : {}", r.unique_ips)?;
    writeln!(
        out,
        "Malformed/blank: {} / {} lines skipped",
        r.malformed_lines, r.blank_lines
    )?;
    writeln!(out, "Total bytes    : {}", r.total_bytes)?;
    writeln!(out, "Mean bytes     : {:.1}", r.mean_bytes)?;
    writeln!(out, "Error rate     : {:.2}% (4xx+5xx)", r.error_rate)?;

    writeln!(out, "\nStatus classes:")?;
    write_counted(&mut out, &r.status_classes)?;

    writeln!(out, "\nTop status codes:")?;
    write_counted(&mut out, &r.top_status_codes)?;

    writeln!(out, "\nTop IPs:")?;
    write_counted(&mut out, &r.top_ips)?;

    writeln!(out, "\nTop paths:")?;
    write_counted(&mut out, &r.top_paths)?;

    writeln!(out, "\nTop methods:")?;
    write_counted(&mut out, &r.top_methods)?;

    writeln!(out, "\nTop user-agents:")?;
    write_counted(&mut out, &r.top_user_agents)?;

    writeln!(out, "\nTop referers:")?;
    write_counted(&mut out, &r.top_referers)?;

    writeln!(out, "\nRequests per hour:")?;
    let max = r
        .requests_per_hour
        .iter()
        .map(|b| b.count)
        .max()
        .unwrap_or(0);
    for b in &r.requests_per_hour {
        let bar_len = if max > 0 {
            (b.count as f64 / max as f64 * 40.0).round() as usize
        } else {
            0
        };
        writeln!(
            out,
            "  {:02}:00  {:>6}  {}",
            b.hour,
            b.count,
            "#".repeat(bar_len)
        )?;
    }

    Ok(())
}

/// Render the human-readable `--group` report.
fn print_group_report(r: &GroupReport) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "log-stats group report")?;
    writeln!(out, "{}", "=".repeat(52))?;
    writeln!(out, "Pattern       : {}", r.pattern)?;
    writeln!(
        out,
        "Matched lines : {} / {}",
        r.matched_lines, r.total_lines
    )?;
    writeln!(out, "\nGroup frequency:")?;
    write_counted(&mut out, &r.groups)?;
    Ok(())
}
