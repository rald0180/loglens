package loglens;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TrafficReportTest {

    private static final Instant T0 = Instant.parse("2026-08-12T00:00:00Z");

    private static LogEntry entry(String ip, String path, int status, long durationMs) {
        return new LogEntry(ip, T0, "GET", path, status, 100L, durationMs);
    }

    @Test
    void countsRequestsAndBytes() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/a", 200, 5));
        r.accept(entry("10.0.0.2", "/b", 200, 7));

        assertEquals(2, r.totalRequests());
        assertEquals(200L, r.totalBytes());
    }

    @Test
    void separatesClientErrorsFromServerErrors() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/a", 200, 1));
        r.accept(entry("10.0.0.1", "/b", 404, 1));
        r.accept(entry("10.0.0.1", "/c", 500, 1));
        r.accept(entry("10.0.0.1", "/d", 200, 1));

        assertEquals(0.5, r.errorRate(), 1e-9);
        assertEquals(0.25, r.serverErrorRate(), 1e-9);
    }

    @Test
    void emptyReportHasZeroErrorRateRatherThanDividingByZero() {
        TrafficReport r = new TrafficReport();

        assertEquals(0.0, r.errorRate(), 1e-9);
        assertEquals(0.0, r.serverErrorRate(), 1e-9);
        assertTrue(r.latency().isEmpty());
    }

    @Test
    void topPathsAreOrderedByCount() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/popular", 200, 1));
        r.accept(entry("10.0.0.1", "/popular", 200, 1));
        r.accept(entry("10.0.0.1", "/popular", 200, 1));
        r.accept(entry("10.0.0.1", "/rare", 200, 1));

        Map<String, Long> top = r.topPaths(2);
        assertEquals(2, top.size());
        assertEquals("/popular", top.keySet().iterator().next());
        assertEquals(3L, top.get("/popular"));
    }

    @Test
    void tiesBreakOnNameSoOutputIsStableBetweenRuns() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/b", 200, 1));
        r.accept(entry("10.0.0.1", "/a", 200, 1));
        r.accept(entry("10.0.0.1", "/c", 200, 1));

        assertEquals("/a", r.topPaths(3).keySet().iterator().next());
    }

    @Test
    void entriesWithoutADurationAreLeftOutOfTheLatencySample() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/a", 200, 10));
        r.accept(entry("10.0.0.1", "/b", 200, -1));
        r.accept(entry("10.0.0.1", "/c", 200, 30));

        assertEquals(2, r.latency().size());
    }

    @Test
    void growsTheDurationBufferBeyondItsInitialCapacity() {
        TrafficReport r = new TrafficReport();
        for (int i = 0; i < 5000; i++) {
            r.accept(entry("10.0.0.1", "/a", 200, i));
        }

        assertEquals(5000, r.latency().size());
        assertEquals(4999L, r.latency().max());
    }

    @Test
    void malformedLinesAreCountedSeparatelyFromRequests() {
        TrafficReport r = new TrafficReport();
        r.accept(entry("10.0.0.1", "/a", 200, 1));
        r.recordMalformedLine();
        r.recordMalformedLine();

        assertEquals(1, r.totalRequests());
        assertEquals(2, r.malformedLines());
    }
}
