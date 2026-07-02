//! Aggregation over a stream of parsed [`Entry`] values.
//!
//! Everything here is a pure function over an iterator of entries (and the
//! caller-supplied parse-failure counts), so the same code path is exercised
//! by both the CLI and the unit tests.

use std::collections::HashMap;

use serde::Serialize;

use crate::parser::Entry;

/// A `(label, count)` pair used throughout the report for "top N" lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Counted {
    pub key: String,
    pub count: u64,
}

/// The full set of statistics computed from a log stream.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Number of valid entries aggregated.
    pub total_requests: u64,
    /// Non-empty lines that failed to parse.
    pub malformed_lines: u64,
    /// Blank / whitespace-only lines skipped.
    pub blank_lines: u64,
    /// Count of distinct client IPs.
    pub unique_ips: u64,
    /// Most frequent client IPs.
    pub top_ips: Vec<Counted>,
    /// Most frequent request paths.
    pub top_paths: Vec<Counted>,
    /// Most frequent HTTP methods.
    pub top_methods: Vec<Counted>,
    /// Count of responses in each status class (`"2xx"`, `"3xx"`, ...).
    pub status_classes: Vec<Counted>,
    /// Most frequent individual status codes.
    pub top_status_codes: Vec<Counted>,
    /// Most frequent user-agent strings.
    pub top_user_agents: Vec<Counted>,
    /// Most frequent referers.
    pub top_referers: Vec<Counted>,
    /// Sum of all response byte sizes (entries logging `-` contribute 0).
    pub total_bytes: u64,
    /// Mean response size over entries that reported a byte count.
    pub mean_bytes: f64,
    /// Requests bucketed by hour-of-day (0..=23), always 24 entries.
    pub requests_per_hour: Vec<HourBucket>,
    /// Percentage of responses that were 4xx or 5xx.
    pub error_rate: f64,
}

/// One bucket of the requests-per-hour histogram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HourBucket {
    /// Hour of day, 0..=23.
    pub hour: u8,
    pub count: u64,
}

/// Sort a frequency map into a descending `(key, count)` list, keeping at most
/// `top` items. Ties are broken by key for deterministic output.
fn top_n(map: HashMap<String, u64>, top: usize) -> Vec<Counted> {
    let mut v: Vec<Counted> = map
        .into_iter()
        .map(|(key, count)| Counted { key, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    v.truncate(top);
    v
}

/// Compute the full [`Report`] from an iterator of valid entries.
///
/// `malformed_lines` / `blank_lines` are passed in by the caller (which owns
/// the raw line stream and the parse step) so this function stays a pure fold
/// over already-parsed entries.
pub fn aggregate<'a, I>(entries: I, top: usize, malformed_lines: u64, blank_lines: u64) -> Report
where
    I: IntoIterator<Item = &'a Entry>,
{
    let mut total_requests: u64 = 0;
    let mut ip_counts: HashMap<String, u64> = HashMap::new();
    let mut path_counts: HashMap<String, u64> = HashMap::new();
    let mut method_counts: HashMap<String, u64> = HashMap::new();
    let mut code_counts: HashMap<String, u64> = HashMap::new();
    let mut class_counts: HashMap<u8, u64> = HashMap::new();
    let mut ua_counts: HashMap<String, u64> = HashMap::new();
    let mut ref_counts: HashMap<String, u64> = HashMap::new();

    let mut total_bytes: u64 = 0;
    let mut bytes_n: u64 = 0;
    let mut error_count: u64 = 0;
    let mut hours = [0u64; 24];

    for e in entries {
        total_requests += 1;

        *ip_counts.entry(e.ip.clone()).or_insert(0) += 1;

        if let Some(p) = &e.path {
            *path_counts.entry(p.clone()).or_insert(0) += 1;
        }
        if let Some(m) = &e.method {
            *method_counts.entry(m.clone()).or_insert(0) += 1;
        }

        *code_counts.entry(e.status.to_string()).or_insert(0) += 1;
        *class_counts.entry(e.status_class()).or_insert(0) += 1;

        if let Some(ua) = &e.user_agent {
            *ua_counts.entry(ua.clone()).or_insert(0) += 1;
        }
        if let Some(r) = &e.referer {
            *ref_counts.entry(r.clone()).or_insert(0) += 1;
        }

        if let Some(b) = e.bytes {
            total_bytes += b;
            bytes_n += 1;
        }

        if e.is_error() {
            error_count += 1;
        }

        if let Some(dt) = e.datetime() {
            use chrono::Timelike;
            hours[dt.hour() as usize] += 1;
        }
    }

    let mean_bytes = if bytes_n > 0 {
        total_bytes as f64 / bytes_n as f64
    } else {
        0.0
    };

    let error_rate = if total_requests > 0 {
        error_count as f64 / total_requests as f64 * 100.0
    } else {
        0.0
    };

    // Status classes rendered as "2xx".."5xx", ascending by class digit.
    let mut classes: Vec<(u8, u64)> = class_counts.into_iter().collect();
    classes.sort_by_key(|(c, _)| *c);
    let status_classes = classes
        .into_iter()
        .map(|(c, count)| Counted {
            key: format!("{c}xx"),
            count,
        })
        .collect();

    let requests_per_hour = hours
        .iter()
        .enumerate()
        .map(|(h, &count)| HourBucket {
            hour: h as u8,
            count,
        })
        .collect();

    Report {
        total_requests,
        malformed_lines,
        blank_lines,
        unique_ips: ip_counts.len() as u64,
        top_ips: top_n(ip_counts, top),
        top_paths: top_n(path_counts, top),
        top_methods: top_n(method_counts, top),
        status_classes,
        top_status_codes: top_n(code_counts, top),
        top_user_agents: top_n(ua_counts, top),
        top_referers: top_n(ref_counts, top),
        total_bytes,
        mean_bytes,
        requests_per_hour,
        error_rate,
    }
}

/// A single request singled out by response size, for the "largest responses"
/// report. Unlike the frequency lists, this identifies *individual* requests
/// rather than aggregating by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SizedRequest {
    /// Response size in bytes (the sort key).
    pub bytes: u64,
    /// HTTP status code of the response.
    pub status: u16,
    /// Request method, e.g. `GET`. `None` when the request line was malformed.
    pub method: Option<String>,
    /// Request path, e.g. `/big.iso`. `None` when the request line was empty.
    pub path: Option<String>,
    /// Client IP that made the request.
    pub ip: String,
}

/// The `top` individual requests with the largest response sizes, descending.
///
/// Entries whose byte count was logged as `-` (i.e. `bytes == None`) are
/// excluded — we only rank responses whose size is actually known. Ties on
/// byte size are broken by path then IP for deterministic output.
pub fn largest_responses<'a, I>(entries: I, top: usize) -> Vec<SizedRequest>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let mut v: Vec<SizedRequest> = entries
        .into_iter()
        .filter_map(|e| {
            e.bytes.map(|bytes| SizedRequest {
                bytes,
                status: e.status,
                method: e.method.clone(),
                path: e.path.clone(),
                ip: e.ip.clone(),
            })
        })
        .collect();
    v.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    v.truncate(top);
    v
}

/// Frequency of a captured regex group across a set of lines.
///
/// Returns the descending `(value, count)` list (capped at `top`) plus the
/// number of lines that matched at all. Used by the generic `--group` mode,
/// which works on *any* log, not just access logs.
pub fn group_by_capture<'a, I>(lines: I, re: &regex::Regex, top: usize) -> (Vec<Counted>, u64)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut matched: u64 = 0;
    for line in lines {
        if let Some(caps) = re.captures(line) {
            // Prefer capture group 1; fall back to the whole match if the
            // pattern has no explicit group.
            let value = caps
                .get(1)
                .or_else(|| caps.get(0))
                .map(|m| m.as_str().to_string());
            if let Some(v) = value {
                matched += 1;
                *counts.entry(v).or_insert(0) += 1;
            }
        }
    }
    (top_n(counts, top), matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_line, LogFormat, ParseOutcome};

    fn entries_from(lines: &[&str]) -> (Vec<Entry>, u64, u64) {
        let mut v = Vec::new();
        let mut malformed = 0;
        let mut blank = 0;
        for l in lines {
            match parse_line(l, LogFormat::Auto) {
                ParseOutcome::Ok(e) => v.push(e),
                ParseOutcome::Malformed => malformed += 1,
                ParseOutcome::Blank => blank += 1,
            }
        }
        (v, malformed, blank)
    }

    const SAMPLE: &[&str] = &[
        r#"10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1000 "-" "UA-A""#,
        r#"10.0.0.1 - - [10/Oct/2000:13:10:00 -0700] "GET /index.html HTTP/1.1" 200 1000 "-" "UA-A""#,
        r#"10.0.0.2 - - [10/Oct/2000:14:00:00 -0700] "GET /about.html HTTP/1.1" 200 2000 "http://x/" "UA-B""#,
        r#"10.0.0.3 - - [10/Oct/2000:14:30:00 -0700] "POST /login HTTP/1.1" 302 0 "-" "UA-A""#,
        r#"10.0.0.4 - - [10/Oct/2000:15:00:00 -0700] "GET /missing HTTP/1.1" 404 500 "-" "UA-C""#,
        r#"10.0.0.5 - - [10/Oct/2000:15:00:00 -0700] "GET /boom HTTP/1.1" 500 0 "-" "UA-C""#,
        r#"10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1000 "-" "UA-A""#,
    ];

    #[test]
    fn total_and_unique() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        assert_eq!(r.total_requests, 7);
        // IPs: .1 (x3), .2, .3, .4, .5 = 5 unique
        assert_eq!(r.unique_ips, 5);
    }

    #[test]
    fn top_path_is_index() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        assert_eq!(r.top_paths[0].key, "/index.html");
        assert_eq!(r.top_paths[0].count, 3);
    }

    #[test]
    fn top_ip_is_dot_one() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        assert_eq!(r.top_ips[0].key, "10.0.0.1");
        assert_eq!(r.top_ips[0].count, 3);
    }

    #[test]
    fn status_distribution() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        // 2xx: 4 (three index + about), 3xx: 1 (login 302), 4xx: 1, 5xx: 1
        let get = |k: &str| {
            r.status_classes
                .iter()
                .find(|c| c.key == k)
                .map(|c| c.count)
        };
        assert_eq!(get("2xx"), Some(4));
        assert_eq!(get("3xx"), Some(1));
        assert_eq!(get("4xx"), Some(1));
        assert_eq!(get("5xx"), Some(1));
    }

    #[test]
    fn top_status_code_is_200() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        assert_eq!(r.top_status_codes[0].key, "200");
        assert_eq!(r.top_status_codes[0].count, 4);
    }

    #[test]
    fn mean_and_total_bytes() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        // bytes: 1000,1000,2000,0,500,0,1000 -> all 7 reported a number
        // total = 5500, mean = 5500/7
        assert_eq!(r.total_bytes, 5500);
        assert!((r.mean_bytes - (5500.0 / 7.0)).abs() < 1e-9);
    }

    #[test]
    fn per_hour_buckets() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        assert_eq!(r.requests_per_hour.len(), 24);
        let h = |hr: u8| {
            r.requests_per_hour
                .iter()
                .find(|b| b.hour == hr)
                .unwrap()
                .count
        };
        // 13:xx -> 3 (two .1 at 13:55 + one .1 at 13:10)
        assert_eq!(h(13), 3);
        // 14:xx -> 2 (about + login)
        assert_eq!(h(14), 2);
        // 15:xx -> 2 (404 + 500)
        assert_eq!(h(15), 2);
        assert_eq!(h(0), 0);
    }

    #[test]
    fn error_rate_is_correct() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        // 2 errors (404 + 500) of 7 = 28.57%
        assert!((r.error_rate - (2.0 / 7.0 * 100.0)).abs() < 1e-9);
    }

    #[test]
    fn top_user_agents() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 10, 0, 0);
        // UA-A appears 4 times
        assert_eq!(r.top_user_agents[0].key, "UA-A");
        assert_eq!(r.top_user_agents[0].count, 4);
    }

    #[test]
    fn malformed_counted_not_fatal() {
        let mut lines: Vec<&str> = SAMPLE.to_vec();
        lines.push("GARBAGE LINE NOT A LOG");
        lines.push("");
        lines.push("   ");
        let (e, malformed, blank) = entries_from(&lines);
        let r = aggregate(&e, 10, malformed, blank);
        assert_eq!(r.total_requests, 7); // unchanged
        assert_eq!(r.malformed_lines, 1);
        assert_eq!(r.blank_lines, 2);
    }

    #[test]
    fn top_n_respects_limit() {
        let (e, _, _) = entries_from(SAMPLE);
        let r = aggregate(&e, 2, 0, 0);
        assert!(r.top_ips.len() <= 2);
        assert!(r.top_paths.len() <= 2);
    }

    #[test]
    fn group_by_capture_works() {
        let lines = [
            "ERROR something failed",
            "INFO all good",
            "ERROR another failure",
            "WARN careful",
            "ERROR third",
        ];
        let re = regex::Regex::new(r"^(\w+)\s").unwrap();
        let (counts, matched) = group_by_capture(lines, &re, 10);
        assert_eq!(matched, 5);
        assert_eq!(counts[0].key, "ERROR");
        assert_eq!(counts[0].count, 3);
    }

    #[test]
    fn largest_responses_ranks_by_bytes() {
        let (e, _, _) = entries_from(SAMPLE);
        let l = largest_responses(&e, 3);
        assert_eq!(l.len(), 3);
        // biggest is /boom? no — SAMPLE bytes: 1000,1000,2000,0,500,0,1000.
        // largest is /about.html at 2000, then three at 1000.
        assert_eq!(l[0].bytes, 2000);
        assert_eq!(l[0].path.as_deref(), Some("/about.html"));
        assert_eq!(l[0].status, 200);
        // descending order
        assert!(l[0].bytes >= l[1].bytes && l[1].bytes >= l[2].bytes);
    }

    #[test]
    fn largest_responses_excludes_missing_bytes() {
        // An entry whose bytes were logged as `-` must not appear.
        let line = r#"9.9.9.9 - - [10/Oct/2000:13:00:00 -0700] "GET /nobytes HTTP/1.1" 200 -"#;
        let (mut e, _, _) = entries_from(SAMPLE);
        e.extend(entries_from(&[line]).0);
        let l = largest_responses(&e, 100);
        assert!(l.iter().all(|r| r.path.as_deref() != Some("/nobytes")));
        // every SAMPLE entry reported a byte count, plus none for the new one
        assert_eq!(l.len(), 7);
    }

    #[test]
    fn largest_responses_respects_top_and_empty() {
        let (e, _, _) = entries_from(SAMPLE);
        assert!(largest_responses(&e, 2).len() <= 2);
        assert!(largest_responses(std::iter::empty::<&Entry>(), 5).is_empty());
    }

    #[test]
    fn empty_input_no_panic() {
        let r = aggregate(std::iter::empty::<&Entry>(), 10, 0, 0);
        assert_eq!(r.total_requests, 0);
        assert_eq!(r.unique_ips, 0);
        assert_eq!(r.mean_bytes, 0.0);
        assert_eq!(r.error_rate, 0.0);
        assert_eq!(r.requests_per_hour.len(), 24);
    }
}
