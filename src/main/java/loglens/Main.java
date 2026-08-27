package loglens;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * Command line entry point.
 *
 * <pre>
 *   loglens &lt;logfile&gt; [--top N] [--auth-threshold N] [--window-seconds N] [--scan-threshold N]
 * </pre>
 */
public final class Main {

    private static final int EXIT_USAGE = 2;
    private static final int EXIT_IO = 3;
    /** Non zero when findings exist, so the tool can gate a CI step or a cron job. */
    private static final int EXIT_FINDINGS = 1;

    public static void main(String[] args) {
        if (args.length == 0 || "--help".equals(args[0])) {
            usage();
            System.exit(EXIT_USAGE);
        }

        Path file = Path.of(args[0]);
        if (!Files.isReadable(file)) {
            System.err.println("cannot read file: " + file);
            System.exit(EXIT_IO);
        }

        int top = 5;
        int authThreshold = DetectorConfig.defaults().authFailureThreshold();
        long windowSeconds = DetectorConfig.defaults().window().toSeconds();
        int scanThreshold = DetectorConfig.defaults().distinctNotFoundThreshold();

        try {
            for (int i = 1; i < args.length; i += 2) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("missing value for " + args[i]);
                }
                String value = args[i + 1];
                switch (args[i]) {
                    case "--top" -> top = Integer.parseInt(value);
                    case "--auth-threshold" -> authThreshold = Integer.parseInt(value);
                    case "--window-seconds" -> windowSeconds = Long.parseLong(value);
                    case "--scan-threshold" -> scanThreshold = Integer.parseInt(value);
                    default -> throw new IllegalArgumentException("unknown option " + args[i]);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(EXIT_USAGE);
        }

        DetectorConfig config = new DetectorConfig(authThreshold, Duration.ofSeconds(windowSeconds), scanThreshold);

        try {
            LogAnalyser.Result result = new LogAnalyser(config).analyse(file);
            print(result, top);
            System.exit(result.findings().isEmpty() ? 0 : EXIT_FINDINGS);
        } catch (IOException e) {
            System.err.println("failed reading " + file + ": " + e.getMessage());
            System.exit(EXIT_IO);
        }
    }

    private static void print(LogAnalyser.Result result, int top) {
        TrafficReport report = result.report();

        System.out.println("TRAFFIC");
        System.out.printf("  requests        %d%n", report.totalRequests());
        System.out.printf("  malformed lines %d%n", report.malformedLines());
        System.out.printf("  bytes sent      %d%n", report.totalBytes());
        System.out.printf("  error rate      %.2f%%  (4xx and 5xx)%n", report.errorRate() * 100);
        System.out.printf("  server errors   %.2f%%  (5xx only)%n", report.serverErrorRate() * 100);

        Percentiles latency = report.latency();
        if (!latency.isEmpty()) {
            System.out.println();
            System.out.println("LATENCY (ms)");
            System.out.printf("  p50 %d   p95 %d   p99 %d   max %d%n",
                    latency.at(50), latency.at(95), latency.at(99), latency.max());
        }

        System.out.println();
        System.out.println("STATUS CODES");
        report.statusCounts().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.printf("  %d  %d%n", e.getKey(), e.getValue()));

        System.out.println();
        System.out.println("TOP ENDPOINTS");
        report.topPaths(top).forEach((path, count) -> System.out.printf("  %-40s %d%n", path, count));

        System.out.println();
        System.out.println("TOP CLIENTS");
        report.topClients(top).forEach((ip, count) -> System.out.printf("  %-40s %d%n", ip, count));

        System.out.println();
        if (result.findings().isEmpty()) {
            System.out.println("FINDINGS  none");
        } else {
            System.out.println("FINDINGS");
            for (Finding f : result.findings()) {
                System.out.printf("  [%s] %s%n", f.kind(), f.clientIp());
                System.out.printf("      %s%n", f.detail());
                System.out.printf("      between %s and %s%n", f.firstSeen(), f.lastSeen());
            }
        }
    }

    private static void usage() {
        System.err.println("""
                usage: loglens <logfile> [options]

                  --top N              how many endpoints and clients to list   (default 5)
                  --auth-threshold N   401/403 responses in the window to flag  (default 5)
                  --window-seconds N   the sliding window for that count        (default 60)
                  --scan-threshold N   distinct 404 paths from one client to flag (default 15)

                exit codes: 0 clean, 1 findings present, 2 bad usage, 3 io error
                """);
    }
}
