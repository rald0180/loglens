package loglens;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousActivityDetectorTest {

    private static final Instant T0 = Instant.parse("2026-08-12T00:00:00Z");

    private static LogEntry entry(String ip, int secondsOffset, int status, String path) {
        return new LogEntry(ip, T0.plusSeconds(secondsOffset), "GET", path, status, 0L, -1L);
    }

    private static SuspiciousActivityDetector detector(int authThreshold, int windowSeconds, int scanThreshold) {
        return new SuspiciousActivityDetector(
                new DetectorConfig(authThreshold, Duration.ofSeconds(windowSeconds), scanThreshold));
    }

    @Test
    void flagsRepeatedRejectedCredentialsInsideTheWindow() {
        SuspiciousActivityDetector d = detector(3, 60, 15);
        for (int i = 0; i < 3; i++) {
            d.accept(entry("198.51.100.9", i, 401, "/login"));
        }

        List<Finding> findings = d.findings();
        assertEquals(1, findings.size());
        assertEquals(Finding.Kind.CREDENTIAL_STUFFING, findings.get(0).kind());
        assertEquals("198.51.100.9", findings.get(0).clientIp());
        assertEquals(3, findings.get(0).count());
    }

    @Test
    void doesNotFlagFailuresSpreadWiderThanTheWindow() {
        SuspiciousActivityDetector d = detector(3, 60, 15);
        d.accept(entry("198.51.100.9", 0, 401, "/login"));
        d.accept(entry("198.51.100.9", 100, 401, "/login"));
        d.accept(entry("198.51.100.9", 200, 401, "/login"));

        assertTrue(d.findings().isEmpty(), "each failure fell outside the previous one's window");
    }

    @Test
    void countsFailuresPerAddressNotAcrossAllOfThem() {
        SuspiciousActivityDetector d = detector(3, 60, 15);
        d.accept(entry("10.0.0.1", 0, 401, "/login"));
        d.accept(entry("10.0.0.2", 1, 403, "/login"));
        d.accept(entry("10.0.0.3", 2, 401, "/login"));

        assertTrue(d.findings().isEmpty(), "three different clients failing once each is not an attack");
    }

    @Test
    void treats403AsAnAuthFailureAlongside401() {
        SuspiciousActivityDetector d = detector(2, 60, 15);
        d.accept(entry("10.0.0.1", 0, 401, "/admin"));
        d.accept(entry("10.0.0.1", 1, 403, "/admin"));

        assertEquals(1, d.findings().size());
    }

    @Test
    void reportsEachAddressOnceNotOncePerRequestAfterTheThreshold() {
        SuspiciousActivityDetector d = detector(2, 60, 15);
        for (int i = 0; i < 10; i++) {
            d.accept(entry("10.0.0.1", i, 401, "/login"));
        }

        assertEquals(1, d.findings().size(), "a noisy attacker should produce one finding, not eight");
    }

    @Test
    void flagsOneClientProbingManyMissingPaths() {
        SuspiciousActivityDetector d = detector(5, 60, 4);
        d.accept(entry("203.0.113.5", 0, 404, "/.env"));
        d.accept(entry("203.0.113.5", 1, 404, "/wp-admin"));
        d.accept(entry("203.0.113.5", 2, 404, "/.git/config"));
        d.accept(entry("203.0.113.5", 3, 404, "/admin.php"));

        List<Finding> findings = d.findings();
        assertEquals(1, findings.size());
        assertEquals(Finding.Kind.PATH_SCANNING, findings.get(0).kind());
        assertEquals(4, findings.get(0).count());
        assertEquals(T0, findings.get(0).firstSeen());
        assertEquals(T0.plusSeconds(3), findings.get(0).lastSeen());
    }

    @Test
    void repeatedlyRequestingTheSameMissingPathIsNotScanning() {
        SuspiciousActivityDetector d = detector(5, 60, 3);
        for (int i = 0; i < 20; i++) {
            d.accept(entry("203.0.113.5", i, 404, "/favicon.ico"));
        }

        assertTrue(d.findings().isEmpty(), "a broken link hit twenty times is one missing path, not a scan");
    }

    @Test
    void successfulTrafficProducesNoFindings() {
        SuspiciousActivityDetector d = detector(2, 60, 2);
        for (int i = 0; i < 50; i++) {
            d.accept(entry("10.0.0.1", i, 200, "/api/items"));
        }

        assertTrue(d.findings().isEmpty());
    }

    @Test
    void findingsListIsNotModifiableByCallers() {
        SuspiciousActivityDetector d = detector(1, 60, 15);
        d.accept(entry("10.0.0.1", 0, 401, "/login"));

        assertThrows(UnsupportedOperationException.class, () -> d.findings().clear());
    }
}
