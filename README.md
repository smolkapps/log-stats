# log-stats

A fast Rust CLI to analyze Apache/Nginx web access logs and report rich
statistics — top IPs, paths, status-code distribution, user-agents, referers,
a requests-per-hour histogram, byte totals, and error rate. Reads files or
stdin, emits text or JSON, and includes a generic `--group` mode that computes
the frequency of any regex capture group across arbitrary log lines.

Zero network access. Pure local analysis.

## Install / build

```sh
cargo build --release
# binary at ./target/release/log-stats
```

## Usage

```sh
log-stats [OPTIONS] [FILES]...
```

If no files are given (or `-`), input is read from **stdin**.

### Options

| Flag | Description |
|------|-------------|
| `--top N` | Items per "top" list (default `10`). |
| `--json` | Emit machine-readable JSON instead of a text report. |
| `--status CODE` | Only include requests with this exact HTTP status. |
| `--since TIME` | Only include requests at/after `TIME` (inclusive). |
| `--until TIME` | Only include requests before `TIME` (exclusive). |
| `--format FMT` | `combined`, `common`, or `auto` (default, detects from the first lines). |
| `--group REGEX` | Generic mode: frequency of capture group 1 across all input lines. |
| `--largest` | Also report the `--top` individual requests with the largest response sizes (by bytes). |

`TIME` accepts the CLF stamp (`10/Oct/2000:13:55:36 -0700`), ISO-8601
(`2000-10-10T13:55:36-07:00`), `YYYY-MM-DD HH:MM:SS` (UTC), or `YYYY-MM-DD`.

### Supported log formats

**Combined** (CLF + referer + user-agent):

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/5.0"
```

**Common** (CLF):

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```

Malformed lines are counted and skipped, never fatal.

## Examples

```sh
# Full report on an access log
log-stats /var/log/nginx/access.log

# Top 5, JSON, only 404s
log-stats access.log --top 5 --status 404 --json

# Restrict to a time window
log-stats access.log --since "2000-10-10 14:00:00" --until "2000-10-10 15:00:00"

# Pipe in and analyze
cat access.log | log-stats

# Generic: count log levels in any log
log-stats app.log --group '^\S+ \S+ (\w+)'

# Surface the heaviest responses (bandwidth hogs)
log-stats access.log --largest --top 5
```

## JSON shape

`--json` emits a single object with: `total_requests`, `malformed_lines`,
`blank_lines`, `unique_ips`, `top_ips`, `top_paths`, `top_methods`,
`status_classes`, `top_status_codes`, `top_user_agents`, `top_referers`,
`total_bytes`, `mean_bytes`, `requests_per_hour` (24 buckets), and
`error_rate`. Each "top" list is an array of `{ "key": ..., "count": ... }`.
With `--largest`, an additional `largest_responses` array is included, each
element `{ "bytes", "status", "method", "path", "ip" }`.

`--group --json` emits `{ pattern, matched_lines, total_lines, groups }`.

## Architecture

- `src/parser.rs` — combined/common log-line parser (pure, regex-based).
- `src/stats.rs` — pure aggregation over an iterator of parsed entries.
- `src/lib.rs` — time-window filter + library re-exports.
- `src/main.rs` — thin CLI shell (clap derive, I/O, rendering).

## Tests

```sh
cargo test
```

Unit tests cover parsing (combined/common/malformed/blank, request-line edge
cases, timestamps), aggregation (counts, top-N, status distribution, mean
bytes, per-hour buckets, error rate, `--group`), and time filtering.
Integration tests (`tests/cli.rs`, via `assert_cmd`) drive the real binary over
stdin and files with `--top`, `--status`, `--since/--until`, `--json`, and
`--group`.

## License

MIT — see [LICENSE](LICENSE).
