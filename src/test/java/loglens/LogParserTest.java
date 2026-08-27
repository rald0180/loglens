package loglens;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {

    private final LogParser parser = new LogParser();

    @Test
    void parsesACombinedFormatLineWithDuration() {
        Optional<LogEntry> parsed = parser.parse(
                "203.0.113.7 - alice [12/Aug/2026:09:14:02 +1000] \"GET /health HTTP/1.1\" 200 1043 12");

        assertTrue(parsed.isPresent());
        LogEntry entry = parsed.get();
        assertEquals("203.0.113.7", entry.clientIp());
        assertEquals("GET", entry.method());
        assertEquals("/health", entry.path());
        assertEquals(200, entry.status());
        assertEquals(1043L, entry.bytesSent());
        assertEquals(12L, entry.durationMs());
        assertEquals(Instant.parse("2026-08-11T23:14:02Z"), entry.timestamp());
    }

    @Test
    void durationIsOptional() {
        LogEntry entry = parser.parse(
                "203.0.113.7 - - [12/Aug/2026:09:14:02 +1000] \"GET /health HTTP/1.1\" 200 1043").orElseThrow();

        assertFalse(entry.hasDuration());
        assertEquals(-1L, entry.durationMs());
    }

    @Test
    void treatsADashBodySizeAsZeroBytes() {
        LogEntry entry = parser.parse(
                "203.0.113.7 - - [12/Aug/2026:09:14:02 +1000] \"HEAD /health HTTP/1.1\" 304 -").orElseThrow();

        assertEquals(0L, entry.bytesSent());
    }

    @Test
    void stripsTheQueryStringSoEndpointsGroupTogether() {
        LogEntry a = parser.parse(
                "10.0.0.1 - - [12/Aug/2026:09:14:02 +1000] \"GET /search?q=cat HTTP/1.1\" 200 10").orElseThrow();
        LogEntry b = parser.parse(
                "10.0.0.1 - - [12/Aug/2026:09:14:03 +1000] \"GET /search?q=dog HTTP/1.1\" 200 10").orElseThrow();

        assertEquals(a.path(), b.path());
        assertEquals("/search", a.path());
    }

    @Test
    void rejectsMalformedLinesInsteadOfThrowing() {
        assertTrue(parser.parse("this is not a log line").isEmpty());
        assertTrue(parser.parse("").isEmpty());
        assertTrue(parser.parse(null).isEmpty());
        assertTrue(parser.parse("203.0.113.7 - - [nonsense] \"GET / HTTP/1.1\" 200 10").isEmpty());
    }

    @Test
    void rejectsAnImpossibleStatusCode() {
        assertTrue(parser.parse(
                "203.0.113.7 - - [12/Aug/2026:09:14:02 +1000] \"GET / HTTP/1.1\" 999 10").isEmpty());
    }
}
