//! End-to-end CLI tests driving the actual `log-stats` binary via `assert_cmd`,
//! exercising file input, stdin, `--top`, `--status`, `--json`, and `--group`.
//!
//! The fixture `tests/data/sample_combined.log` has 9 valid combined-format
//! entries, 1 malformed line and 1 blank line. Verified tallies:
//!   - IPs: .10 x3, .11 x2, .12 x2, .13 x1, .14 x1  => 5 unique, top = .10 (3)
//!   - paths: /index.html x3 (top), rest x1
//!   - status classes: 2xx=5, 3xx=2, 4xx=1, 5xx=1
//!   - bytes reported on 8 entries, sum 13613, mean 1701.625
//!   - errors: 2 of 9 => 22.22%

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn sample_path() -> String {
    format!(
        "{}/tests/data/sample_combined.log",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn sample_text() -> String {
    std::fs::read_to_string(sample_path()).expect("read sample log")
}

#[test]
fn text_report_has_core_numbers() {
    Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total requests : 9"))
        .stdout(predicate::str::contains("Unique IPs     : 5"))
        .stdout(predicate::str::contains("Malformed/blank: 1 / 1"))
        .stdout(predicate::str::contains("Error rate     : 22.22%"));
}

#[test]
fn json_output_shape_and_values() {
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());

    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");

    assert_eq!(v["total_requests"], 9);
    assert_eq!(v["unique_ips"], 5);
    assert_eq!(v["malformed_lines"], 1);
    assert_eq!(v["blank_lines"], 1);
    assert_eq!(v["total_bytes"], 13613);

    // mean_bytes = 13613 / 8 = 1701.625
    let mean = v["mean_bytes"].as_f64().unwrap();
    assert!((mean - 1701.625).abs() < 1e-6, "mean was {mean}");

    // error_rate = 2/9*100
    let err = v["error_rate"].as_f64().unwrap();
    assert!(
        (err - (2.0 / 9.0 * 100.0)).abs() < 1e-6,
        "error_rate was {err}"
    );

    // top path
    assert_eq!(v["top_paths"][0]["key"], "/index.html");
    assert_eq!(v["top_paths"][0]["count"], 3);

    // top ip
    assert_eq!(v["top_ips"][0]["key"], "192.168.1.10");
    assert_eq!(v["top_ips"][0]["count"], 3);

    // status classes present with correct counts
    let classes = v["status_classes"].as_array().unwrap();
    let get_class = |name: &str| -> Option<i64> {
        classes
            .iter()
            .find(|c| c["key"] == name)
            .and_then(|c| c["count"].as_i64())
    };
    assert_eq!(get_class("2xx"), Some(5));
    assert_eq!(get_class("3xx"), Some(2));
    assert_eq!(get_class("4xx"), Some(1));
    assert_eq!(get_class("5xx"), Some(1));

    // requests_per_hour always 24 buckets; verify the populated ones
    let hours = v["requests_per_hour"].as_array().unwrap();
    assert_eq!(hours.len(), 24);
    let hour_count = |h: i64| -> i64 {
        hours
            .iter()
            .find(|b| b["hour"] == h)
            .and_then(|b| b["count"].as_i64())
            .unwrap()
    };
    assert_eq!(hour_count(13), 2);
    assert_eq!(hour_count(14), 3);
    assert_eq!(hour_count(15), 3);
    assert_eq!(hour_count(16), 1);
    assert_eq!(hour_count(0), 0);
}

#[test]
fn reads_from_stdin() {
    Command::cargo_bin("log-stats")
        .unwrap()
        .write_stdin(sample_text())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total requests : 9"));
}

#[test]
fn top_flag_limits_lists() {
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--top")
        .arg("1")
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["top_ips"].as_array().unwrap().len(), 1);
    assert_eq!(v["top_paths"].as_array().unwrap().len(), 1);
    // the single remaining entry is still the most frequent
    assert_eq!(v["top_paths"][0]["key"], "/index.html");
}

#[test]
fn status_filter_selects_only_matching() {
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--status")
        .arg("404")
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    // exactly one 404 in the fixture
    assert_eq!(v["total_requests"], 1);
    assert_eq!(v["top_paths"][0]["key"], "/missing-page");
    // that single request is a 4xx -> error rate 100%
    let err = v["error_rate"].as_f64().unwrap();
    assert!((err - 100.0).abs() < 1e-9);
}

#[test]
fn group_mode_counts_capture() {
    // Frequency of log levels in a generic (non-access) log via stdin.
    let generic = "ERROR disk full\nINFO started\nERROR timeout\nWARN slow\nERROR oom\nINFO ok\n";
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg("--group")
        .arg(r"^(\w+)\s")
        .arg("--json")
        .write_stdin(generic)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matched_lines"], 6);
    assert_eq!(v["total_lines"], 6);
    assert_eq!(v["groups"][0]["key"], "ERROR");
    assert_eq!(v["groups"][0]["count"], 3);
}

#[test]
fn group_mode_text_output() {
    let generic = "GET /a\nGET /b\nPOST /c\n";
    Command::cargo_bin("log-stats")
        .unwrap()
        .arg("--group")
        .arg(r"^(\S+)\s")
        .write_stdin(generic)
        .assert()
        .success()
        .stdout(predicate::str::contains("group report"))
        .stdout(predicate::str::contains("GET"));
}

#[test]
fn explicit_common_format_rejects_combined_tail() {
    // Forcing --format common on combined lines means none parse as valid;
    // they all become malformed (counted, not fatal).
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--format")
        .arg("common")
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["total_requests"], 0);
    // 9 previously-valid combined lines are now malformed, plus the 1 already-bad line
    assert_eq!(v["malformed_lines"], 10);
}

#[test]
fn invalid_format_errors_out() {
    Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--format")
        .arg("bogus")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid --format"));
}

#[test]
fn since_until_time_filter() {
    // Window [14:00, 15:00) PDT -> only the three 14:xx requests.
    let out = Command::cargo_bin("log-stats")
        .unwrap()
        .arg(sample_path())
        .arg("--since")
        .arg("10/Oct/2000:14:00:00 -0700")
        .arg("--until")
        .arg("10/Oct/2000:15:00:00 -0700")
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["total_requests"], 3);
}

#[test]
fn missing_file_errors() {
    Command::cargo_bin("log-stats")
        .unwrap()
        .arg("/nonexistent/path/to/file.log")
        .assert()
        .failure()
        .stderr(predicate::str::contains("opening log file"));
}
