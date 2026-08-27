# loglens

A command line tool that reads a web server access log and tells you two things
in one pass: how the service is behaving, and which clients are behaving badly.

Access logs are the cheapest telemetry a service produces and usually the least
read. `loglens` turns one into a short report you can look at in ten seconds:
error rate, latency percentiles, busiest endpoints, and a findings list for
clients that look like they are guessing credentials or probing for paths that
should not exist.

```
$ loglens sample/access.log

TRAFFIC
  requests        95
  malformed lines 1
  bytes sent      139565
  error rate      31.58%  (4xx and 5xx)
  server errors   4.21%  (5xx only)

LATENCY (ms)
  p50 13   p95 209   p99 886   max 886

STATUS CODES
  200  65
  401  9
  404  17
  500  4

TOP ENDPOINTS
  /api/items                               23
  /login                                   19
  /static/app.js                           10

TOP CLIENTS
  203.0.113.23                             17
  203.0.113.77                             16
  10.0.0.5                                 15

FINDINGS
  [CREDENTIAL_STUFFING] 198.51.100.9
      5 rejected credentials within 60s
      between 2026-08-11T23:00:40Z and 2026-08-11T23:00:52Z
  [PATH_SCANNING] 203.0.113.77
      15 distinct missing paths requested
      between 2026-08-11T23:02:00Z and 2026-08-11T23:02:14Z
```

## Running it

Requires Java 17 or newer and Maven.

```bash
mvn package
java -jar target/loglens-1.0.0.jar sample/access.log
```

Options:

```
--top N              how many endpoints and clients to list      (default 5)
--auth-threshold N   401/403 responses in the window to flag     (default 5)
--window-seconds N   the sliding window for that count           (default 60)
--scan-threshold N   distinct 404 paths from one client to flag  (default 15)
```

Exit codes: `0` clean, `1` findings present, `2` bad usage, `3` io error. The
non zero exit on findings is deliberate, so the tool can gate a cron job or a
pipeline step without anything having to parse its output.

## Input format

Common Log Format and Combined Log Format, with an optional trailing request
duration in milliseconds:

```
203.0.113.7 - alice [12/Aug/2026:09:14:02 +1000] "GET /health HTTP/1.1" 200 1043 12
```

## Design notes

**One pass, streaming.** The file is read line by line with a `BufferedReader`
and both the traffic report and the detector are fed from the same loop.
Nothing holds the whole log in memory. Access logs are routinely larger than
heap, and `Files.readAllLines` is the most common way a tool that worked on a
sample falls over on production data. Memory is bounded by the number of
distinct paths and client addresses, not by the number of lines.

**Malformed lines are counted, not fatal.** `LogParser.parse` returns
`Optional<LogEntry>` rather than throwing. Real logs contain truncated and
interleaved lines from rotation, and one bad line should never abort the
analysis of a two gigabyte file. The rejects are counted and printed, so the
damage is visible in the report instead of silently swallowed.

**Sliding window as an ArrayDeque.** Credential stuffing detection keeps one
deque of failure timestamps per client address. Each new failure evicts
everything older than the window from the head, then compares the remaining
size to the threshold. Both ends of a deque are O(1), so the check is O(1)
amortised per failure. A list would make eviction O(n); a sorted structure
would be wasted work, because log lines already arrive in time order.

**Nearest rank percentiles.** `Percentiles` returns a value that actually
occurred in the sample rather than interpolating between two. Interpolation can
report a p99 that no single request ever hit, which is misleading when the
number you are chasing is a real slow request you want to go and find.

**Distinct paths, not request count, for scanning.** A broken link hit two
hundred times is one missing path, not a scan. The detector counts distinct
404 paths per client so ordinary breakage does not drown the signal.

**Immutable entries.** `LogEntry` is a record with a validating constructor.
Once a line is parsed and validated, no later stage has a legitimate reason to
change it, so immutability removes a class of bug from the report builders.

## Tests

```bash
mvn test
```

Coverage is on the behaviour that matters rather than on line count: parser
rejection of every malformed shape, percentile edge cases (empty sample, single
sample, out of range percentile), window boundaries in both directions, the
difference between one attacker and three unlucky users, and the fact that a
noisy attacker produces one finding rather than one per request.

## Limitations

- Assumes entries arrive in non decreasing time order, which holds for a single
  access log but not for a merged multi host file.
- IPv6 addresses parse as opaque strings; no subnet grouping.
- No JSON output yet, which is the first thing needed to feed this into anything
  else.

## Next

- JSON and CSV output modes
- Group findings by subnet so a distributed attempt from one range reads as one finding
- Follow mode (`--follow`) for a live tail
- Configurable path normalisation, so `/users/1` and `/users/2` group as `/users/{id}`

## Licence

MIT
