//! Parsing of Apache/Nginx access-log lines in the **common** and **combined**
//! log formats.
//!
//! Common Log Format (CLF):
//! ```text
//! 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
//! ```
//!
//! Combined Log Format = CLF + `"referer"` + `"user-agent"`:
//! ```text
//! 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/5.0"
//! ```

use chrono::{DateTime, FixedOffset};
use std::sync::OnceLock;

use regex::Regex;

/// Which access-log dialect to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Common Log Format (no referer / user-agent).
    Common,
    /// Combined Log Format (CLF + referer + user-agent).
    Combined,
    /// Try combined first, fall back to common, per line.
    Auto,
}

impl LogFormat {
    /// Parse a `--format` string value into a [`LogFormat`].
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "common" => Some(LogFormat::Common),
            "combined" => Some(LogFormat::Combined),
            "auto" => Some(LogFormat::Auto),
            _ => None,
        }
    }
}

/// A single successfully-parsed access-log entry.
///
/// Fields that are absent in the source line (or recorded by the server as
/// `-`) are represented as [`None`] where it makes semantic sense (e.g.
/// `user`, `bytes`, `referer`, `user_agent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Client IP address (or hostname), the first field of the line.
    pub ip: String,
    /// RFC 1413 identity of the client; almost always `-`.
    pub ident: Option<String>,
    /// Authenticated user id (HTTP basic auth), or `None` when `-`.
    pub user: Option<String>,
    /// Raw timestamp text exactly as it appeared between the brackets.
    pub time_raw: String,
    /// HTTP method, e.g. `GET`. `None` when the request line is malformed/empty.
    pub method: Option<String>,
    /// Request path / target, e.g. `/index.html`.
    pub path: Option<String>,
    /// Protocol, e.g. `HTTP/1.1`.
    pub protocol: Option<String>,
    /// HTTP status code returned to the client.
    pub status: u16,
    /// Response size in bytes. `None` when the server logged `-`.
    pub bytes: Option<u64>,
    /// Referer header (combined format only).
    pub referer: Option<String>,
    /// User-Agent header (combined format only).
    pub user_agent: Option<String>,
}

impl Entry {
    /// Parse the bracketed timestamp into a timezone-aware [`DateTime`].
    ///
    /// The expected layout is the standard CLF stamp
    /// `10/Oct/2000:13:55:36 -0700`. Returns `None` if it cannot be parsed.
    pub fn datetime(&self) -> Option<DateTime<FixedOffset>> {
        DateTime::parse_from_str(&self.time_raw, "%d/%b/%Y:%H:%M:%S %z").ok()
    }

    /// The status-code class as a single leading digit (`2`,`3`,`4`,`5`, ...).
    pub fn status_class(&self) -> u8 {
        (self.status / 100) as u8
    }

    /// Whether this entry represents an error response (4xx or 5xx).
    pub fn is_error(&self) -> bool {
        let c = self.status_class();
        c == 4 || c == 5
    }
}

/// Outcome of attempting to parse a single line.
///
/// The `Ok` variant is intentionally not boxed: it is the overwhelmingly
/// common case on the parse hot path, so boxing it to equalise variant sizes
/// would add an allocation per parsed line to satisfy a lint about the rare
/// variants. We accept the size difference instead.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Line parsed into a valid [`Entry`].
    Ok(Entry),
    /// Line was non-empty but did not match any known format.
    Malformed,
    /// Line was empty / whitespace-only and should be ignored entirely.
    Blank,
}

// The combined-format regex. Built once, lazily.
//
// Breakdown:
//   (\S+)                         ip
//   (\S+)                         ident
//   (\S+)                         user
//   \[([^\]]+)\]                  time (anything but a closing bracket)
//   "([^"]*)"                     request line (may be empty)
//   (\d{3}|-)                     status (3 digits, or `-` for some proxies)
//   (\d+|-)                       bytes
// Optionally followed by the two combined-format quoted fields:
//   "((?:[^"\\]|\\.)*)"           referer  (allows escaped quotes)
//   "((?:[^"\\]|\\.)*)"           user-agent
//
// The referer/user-agent group is optional so the same regex handles both
// common and combined lines; `auto` and `common` callers simply ignore the
// trailing captures.
fn line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^
            (\S+)\s+                       # 1 ip
            (\S+)\s+                       # 2 ident
            (\S+)\s+                       # 3 user
            \[([^\]]+)\]\s+                # 4 time
            "([^"]*)"\s+                   # 5 request line
            (\d{3}|-)\s+                   # 6 status
            (\d+|-)                        # 7 bytes
            (?:                            #   optional combined tail:
                \s+"((?:[^"\\]|\\.)*)"     # 8 referer
                \s+"((?:[^"\\]|\\.)*)"     # 9 user-agent
            )?
            \s*$
        "#,
        )
        .expect("static log-line regex is valid")
    })
}

/// Normalise a CLF `-` placeholder into `None`, anything else into `Some`.
fn dash_to_none(s: &str) -> Option<String> {
    if s == "-" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Split a request line (`"GET /path HTTP/1.1"`) into (method, path, protocol).
///
/// Real-world logs contain garbage request lines (empty strings, malformed
/// probes, requests with spaces in the path). We split on the first and last
/// space so a path containing spaces still yields a sensible method/protocol;
/// anything we cannot make sense of becomes `None`.
fn split_request(req: &str) -> (Option<String>, Option<String>, Option<String>) {
    let req = req.trim();
    if req.is_empty() {
        return (None, None, None);
    }
    // Method = up to first space.
    let (method, rest) = match req.split_once(' ') {
        Some((m, r)) => (m.to_string(), r),
        None => return (Some(req.to_string()), None, None),
    };
    // Protocol = after the last space (only if it looks like a protocol token).
    match rest.rsplit_once(' ') {
        Some((path, proto)) if proto.starts_with("HTTP/") || proto.starts_with("RTSP/") => (
            Some(method),
            Some(path.to_string()),
            Some(proto.to_string()),
        ),
        // No trailing protocol token: the whole remainder is the path.
        _ => (Some(method), Some(rest.to_string()), None),
    }
}

/// Parse a single log line according to `format`.
///
/// Never panics; unparseable lines yield [`ParseOutcome::Malformed`] and blank
/// lines yield [`ParseOutcome::Blank`] so the caller can count and skip them.
pub fn parse_line(line: &str, format: LogFormat) -> ParseOutcome {
    if line.trim().is_empty() {
        return ParseOutcome::Blank;
    }

    let caps = match line_re().captures(line) {
        Some(c) => c,
        None => return ParseOutcome::Malformed,
    };

    let has_combined_tail = caps.get(8).is_some() && caps.get(9).is_some();

    // Enforce the explicitly requested dialect. `Auto` accepts either shape.
    match format {
        LogFormat::Combined if !has_combined_tail => return ParseOutcome::Malformed,
        LogFormat::Common if has_combined_tail => return ParseOutcome::Malformed,
        _ => {}
    }

    let ip = caps[1].to_string();
    let ident = dash_to_none(&caps[2]);
    let user = dash_to_none(&caps[3]);
    let time_raw = caps[4].to_string();
    let (method, path, protocol) = split_request(&caps[5]);

    let status: u16 = match caps[6].parse() {
        Ok(s) => s,
        // A `-` status is not useful for our stats; treat the line as malformed.
        Err(_) => return ParseOutcome::Malformed,
    };

    let bytes = match &caps[7] {
        "-" => None,
        n => n.parse::<u64>().ok(),
    };

    let referer = caps.get(8).and_then(|m| dash_to_none(m.as_str()));
    let user_agent = caps.get(9).and_then(|m| dash_to_none(m.as_str()));

    ParseOutcome::Ok(Entry {
        ip,
        ident,
        user,
        time_raw,
        method,
        path,
        protocol,
        status,
        bytes,
        referer,
        user_agent,
    })
}

/// Auto-detect the most likely format from a sample of lines.
///
/// Scans up to `sample` non-blank lines; if any parse as combined we report
/// [`LogFormat::Combined`], otherwise [`LogFormat::Common`]. An empty/garbage
/// sample defaults to [`LogFormat::Combined`] (the most common case on the web).
pub fn detect_format<'a>(lines: impl IntoIterator<Item = &'a str>, sample: usize) -> LogFormat {
    let mut saw_common = false;
    let mut checked = 0usize;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if checked >= sample {
            break;
        }
        checked += 1;
        if let ParseOutcome::Ok(_) = parse_line(line, LogFormat::Auto) {
            if let Some(c) = line_re().captures(line) {
                if c.get(8).is_some() && c.get(9).is_some() {
                    return LogFormat::Combined;
                } else {
                    saw_common = true;
                }
            }
        }
    }
    if saw_common {
        LogFormat::Common
    } else {
        LogFormat::Combined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMBINED: &str = r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (X11)""#;
    const COMMON: &str =
        r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#;

    #[test]
    fn parses_combined_line() {
        match parse_line(COMBINED, LogFormat::Combined) {
            ParseOutcome::Ok(e) => {
                assert_eq!(e.ip, "127.0.0.1");
                assert_eq!(e.ident, None);
                assert_eq!(e.user, Some("frank".into()));
                assert_eq!(e.time_raw, "10/Oct/2000:13:55:36 -0700");
                assert_eq!(e.method.as_deref(), Some("GET"));
                assert_eq!(e.path.as_deref(), Some("/apache_pb.gif"));
                assert_eq!(e.protocol.as_deref(), Some("HTTP/1.0"));
                assert_eq!(e.status, 200);
                assert_eq!(e.bytes, Some(2326));
                assert_eq!(e.referer.as_deref(), Some("http://example.com/start.html"));
                assert_eq!(e.user_agent.as_deref(), Some("Mozilla/5.0 (X11)"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn parses_common_line() {
        match parse_line(COMMON, LogFormat::Common) {
            ParseOutcome::Ok(e) => {
                assert_eq!(e.ip, "127.0.0.1");
                assert_eq!(e.status, 200);
                assert_eq!(e.bytes, Some(2326));
                assert_eq!(e.referer, None);
                assert_eq!(e.user_agent, None);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn datetime_parses() {
        if let ParseOutcome::Ok(e) = parse_line(COMBINED, LogFormat::Combined) {
            let dt = e.datetime().expect("valid timestamp");
            assert_eq!(
                dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                "2000-10-10 13:55:36"
            );
        } else {
            panic!("parse failed");
        }
    }

    #[test]
    fn dash_bytes_is_none() {
        let line = r#"1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 304 -"#;
        if let ParseOutcome::Ok(e) = parse_line(line, LogFormat::Common) {
            assert_eq!(e.bytes, None);
            assert_eq!(e.status, 304);
        } else {
            panic!("parse failed");
        }
    }

    #[test]
    fn blank_line_is_blank() {
        assert_eq!(parse_line("   ", LogFormat::Auto), ParseOutcome::Blank);
        assert_eq!(parse_line("", LogFormat::Auto), ParseOutcome::Blank);
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(
            parse_line("this is not a log line", LogFormat::Auto),
            ParseOutcome::Malformed
        );
    }

    #[test]
    fn combined_strict_rejects_common() {
        assert_eq!(
            parse_line(COMMON, LogFormat::Combined),
            ParseOutcome::Malformed
        );
    }

    #[test]
    fn common_strict_rejects_combined() {
        assert_eq!(
            parse_line(COMBINED, LogFormat::Common),
            ParseOutcome::Malformed
        );
    }

    #[test]
    fn auto_accepts_both() {
        assert!(matches!(
            parse_line(COMBINED, LogFormat::Auto),
            ParseOutcome::Ok(_)
        ));
        assert!(matches!(
            parse_line(COMMON, LogFormat::Auto),
            ParseOutcome::Ok(_)
        ));
    }

    #[test]
    fn request_with_spaces_in_path() {
        let line = r#"1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /a b c HTTP/1.1" 200 5"#;
        if let ParseOutcome::Ok(e) = parse_line(line, LogFormat::Common) {
            assert_eq!(e.method.as_deref(), Some("GET"));
            assert_eq!(e.path.as_deref(), Some("/a b c"));
            assert_eq!(e.protocol.as_deref(), Some("HTTP/1.1"));
        } else {
            panic!("parse failed");
        }
    }

    #[test]
    fn empty_request_line() {
        let line = r#"1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "" 400 0"#;
        if let ParseOutcome::Ok(e) = parse_line(line, LogFormat::Common) {
            assert_eq!(e.method, None);
            assert_eq!(e.path, None);
            assert_eq!(e.status, 400);
        } else {
            panic!("parse failed");
        }
    }

    #[test]
    fn detects_combined() {
        let sample = [COMBINED, COMBINED];
        assert_eq!(detect_format(sample, 5), LogFormat::Combined);
    }

    #[test]
    fn detects_common() {
        let sample = [COMMON, COMMON];
        assert_eq!(detect_format(sample, 5), LogFormat::Common);
    }

    #[test]
    fn status_class_and_error() {
        let mut e = Entry {
            ip: "x".into(),
            ident: None,
            user: None,
            time_raw: "t".into(),
            method: None,
            path: None,
            protocol: None,
            status: 404,
            bytes: None,
            referer: None,
            user_agent: None,
        };
        assert_eq!(e.status_class(), 4);
        assert!(e.is_error());
        e.status = 200;
        assert_eq!(e.status_class(), 2);
        assert!(!e.is_error());
        e.status = 503;
        assert!(e.is_error());
    }
}
