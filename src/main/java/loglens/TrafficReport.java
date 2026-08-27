package loglens;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Accumulates traffic totals in a single pass.
 *
 * <p>Counters only, no stored entries, so memory stays proportional to the number
 * of distinct paths and addresses rather than the number of lines. Durations are
 * the exception: percentiles need the full sample, so those are kept in a growable
 * long array rather than boxed into a list.</p>
 */
public final class TrafficReport {

    private long totalRequests;
    private long malformedLines;
    private long totalBytes;
    private final Map<Integer, Long> statusCounts = new TreeMap<>();
    private final Map<String, Long> pathCounts = new java.util.HashMap<>();
    private final Map<String, Long> clientCounts = new java.util.HashMap<>();
    private long[] durations = new long[1024];
    private int durationCount;

    public void accept(LogEntry entry) {
        totalRequests++;
        totalBytes += entry.bytesSent();
        statusCounts.merge(entry.status(), 1L, Long::sum);
        pathCounts.merge(entry.path(), 1L, Long::sum);
        clientCounts.merge(entry.clientIp(), 1L, Long::sum);
        if (entry.hasDuration()) {
            addDuration(entry.durationMs());
        }
    }

    private void addDuration(long ms) {
        if (durationCount == durations.length) {
            long[] grown = new long[durations.length * 2];
            System.arraycopy(durations, 0, grown, 0, durations.length);
            durations = grown;
        }
        durations[durationCount++] = ms;
    }

    public void recordMalformedLine() {
        malformedLines++;
    }

    public long totalRequests() {
        return totalRequests;
    }

    public long malformedLines() {
        return malformedLines;
    }

    public long totalBytes() {
        return totalBytes;
    }

    public Map<Integer, Long> statusCounts() {
        return Map.copyOf(statusCounts);
    }

    /** Share of requests that returned 4xx or 5xx, as a fraction between 0 and 1. */
    public double errorRate() {
        if (totalRequests == 0) {
            return 0.0;
        }
        long errors = statusCounts.entrySet().stream()
                .filter(e -> e.getKey() >= 400)
                .mapToLong(Map.Entry::getValue)
                .sum();
        return (double) errors / totalRequests;
    }

    /** Share of requests that returned 5xx specifically. Separated because a 404 storm and a 500 storm mean different things. */
    public double serverErrorRate() {
        if (totalRequests == 0) {
            return 0.0;
        }
        long errors = statusCounts.entrySet().stream()
                .filter(e -> e.getKey() >= 500)
                .mapToLong(Map.Entry::getValue)
                .sum();
        return (double) errors / totalRequests;
    }

    public Percentiles latency() {
        long[] exact = new long[durationCount];
        System.arraycopy(durations, 0, exact, 0, durationCount);
        return new Percentiles(exact);
    }

    public Map<String, Long> topPaths(int n) {
        return top(pathCounts, n);
    }

    public Map<String, Long> topClients(int n) {
        return top(clientCounts, n);
    }

    /** Ties break on the key so the output is stable between runs on the same file. */
    private static Map<String, Long> top(Map<String, Long> counts, int n) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(n)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new));
    }

    public List<String> pathsSeen() {
        return List.copyOf(pathCounts.keySet());
    }
}
