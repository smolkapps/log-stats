//! `log-stats` core library.
//!
//! The crate is split into:
//! - [`parser`]: turning raw access-log lines into [`parser::Entry`] values.
//! - [`stats`]:  pure aggregation over a stream of entries.
//!
//! `main.rs` is a thin CLI shell over these.

pub mod parser;
pub mod stats;

use chrono::{DateTime, FixedOffset};

pub use parser::{detect_format, parse_line, Entry, LogFormat, ParseOutcome};
pub use stats::{
    aggregate, group_by_capture, largest_responses, Counted, HourBucket, Report, SizedRequest,
};

/// A half-open time window `[since, until)` used to filter entries.
///
/// Either bound may be absent. Entries whose timestamp cannot be parsed are
/// *excluded* whenever any bound is set (we can't place them in the window).
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeFilter {
    pub since: Option<DateTime<FixedOffset>>,
    pub until: Option<DateTime<FixedOffset>>,
}

impl TimeFilter {
    /// True when no bound is set, i.e. the filter is a no-op.
    pub fn is_empty(&self) -> bool {
        self.since.is_none() && self.until.is_none()
    }

    /// Whether `entry` falls within the window.
    ///
    /// With no bounds set this is always `true`. With bounds set, an entry
    /// whose timestamp fails to parse returns `false`.
    pub fn matches(&self, entry: &Entry) -> bool {
        if self.is_empty() {
            return true;
        }
        let dt = match entry.datetime() {
            Some(d) => d,
            None => return false,
        };
        if let Some(s) = self.since {
            if dt < s {
                return false;
            }
        }
        if let Some(u) = self.until {
            if dt >= u {
                return false;
            }
        }
        true
    }
}

/// Parse a user-supplied time bound for `--since` / `--until`.
///
/// Accepts, in order of preference:
/// - full CLF stamp: `10/Oct/2000:13:55:36 -0700`
/// - RFC 3339 / ISO 8601: `2000-10-10T13:55:36-07:00` or `...Z`
/// - date + time, assumed UTC: `2000-10-10 13:55:36`
/// - date only, assumed UTC midnight: `2000-10-10`
pub fn parse_time_bound(s: &str) -> anyhow::Result<DateTime<FixedOffset>> {
    let s = s.trim();

    if let Ok(dt) = DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z") {
        return Ok(dt);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt);
    }

    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        let dt = Utc.from_utc_datetime(&ndt);
        return Ok(dt.fixed_offset());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0).expect("midnight is a valid time");
        let dt = Utc.from_utc_datetime(&ndt);
        return Ok(dt.fixed_offset());
    }

    anyhow::bail!(
        "could not parse time '{s}'. Try '10/Oct/2000:13:55:36 -0700', \
         '2000-10-10T13:55:36-07:00', '2000-10-10 13:55:36', or '2000-10-10'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_line, LogFormat, ParseOutcome};

    fn entry(line: &str) -> Entry {
        match parse_line(line, LogFormat::Auto) {
            ParseOutcome::Ok(e) => e,
            other => panic!("parse failed: {other:?}"),
        }
    }

    const E13: &str =
        r#"1.1.1.1 - - [10/Oct/2000:13:00:00 -0700] "GET /a HTTP/1.1" 200 1 "-" "ua""#;
    const E15: &str =
        r#"1.1.1.1 - - [10/Oct/2000:15:00:00 -0700] "GET /b HTTP/1.1" 200 1 "-" "ua""#;

    #[test]
    fn empty_filter_matches_all() {
        let f = TimeFilter::default();
        assert!(f.matches(&entry(E13)));
        assert!(f.matches(&entry(E15)));
    }

    #[test]
    fn since_filters_lower_bound() {
        let f = TimeFilter {
            since: Some(parse_time_bound("10/Oct/2000:14:00:00 -0700").unwrap()),
            until: None,
        };
        assert!(!f.matches(&entry(E13)));
        assert!(f.matches(&entry(E15)));
    }

    #[test]
    fn until_is_exclusive() {
        let f = TimeFilter {
            since: None,
            until: Some(parse_time_bound("10/Oct/2000:15:00:00 -0700").unwrap()),
        };
        assert!(f.matches(&entry(E13)));
        // until is exclusive, so the 15:00:00 entry is out
        assert!(!f.matches(&entry(E15)));
    }

    #[test]
    fn window_both_bounds() {
        let f = TimeFilter {
            since: Some(parse_time_bound("10/Oct/2000:12:00:00 -0700").unwrap()),
            until: Some(parse_time_bound("10/Oct/2000:14:00:00 -0700").unwrap()),
        };
        assert!(f.matches(&entry(E13)));
        assert!(!f.matches(&entry(E15)));
    }

    #[test]
    fn parse_iso_bound() {
        let dt = parse_time_bound("2000-10-10T13:00:00-07:00").unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M").to_string(), "2000-10-10 13:00");
    }

    #[test]
    fn parse_date_only_bound() {
        let dt = parse_time_bound("2000-10-10").unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2000-10-10 00:00:00"
        );
    }

    #[test]
    fn parse_datetime_space_bound() {
        let dt = parse_time_bound("2000-10-10 13:30:00").unwrap();
        assert_eq!(dt.format("%H:%M").to_string(), "13:30");
    }

    #[test]
    fn bad_time_bound_errors() {
        assert!(parse_time_bound("not a time").is_err());
    }

    #[test]
    fn unparseable_timestamp_excluded_when_filtered() {
        // craft an entry with a bogus time_raw
        let mut e = entry(E13);
        e.time_raw = "garbage".into();
        let f = TimeFilter {
            since: Some(parse_time_bound("2000-01-01").unwrap()),
            until: None,
        };
        assert!(!f.matches(&e));
        // but with empty filter it still matches
        assert!(TimeFilter::default().matches(&e));
    }
}
