package loglens;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Common Log Format and Combined Log Format lines, with an optional
 * trailing request duration in milliseconds.
 *
 * <p>Example line:</p>
 * <pre>203.0.113.7 - - [12/Aug/2026:09:14:02 +1000] "GET /health HTTP/1.1" 200 1043 12</pre>
 *
 * <p>A malformed line returns {@link Optional#empty()} rather than throwing. Real
 * access logs contain truncated and interleaved lines, and a single bad line
 * should never abort the analysis of a multi gigabyte file. The caller counts
 * the rejects so the damage is visible in the report instead of silent.</p>
 */
public final class LogParser {

    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] \"([A-Z]+) (\\S+)[^\"]*\" (\\d{3}) (\\S+)(?: (\\d+))?.*$");

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    /**
     * @param line one raw log line
     * @return the parsed entry, or empty if the line does not match the expected shape
     */
    public Optional<LogEntry> parse(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        Matcher m = LINE.matcher(line.strip());
        if (!m.matches()) {
            return Optional.empty();
        }
        try {
            Instant timestamp = OffsetDateTime.parse(m.group(3), TIMESTAMP).toInstant();
            int status = Integer.parseInt(m.group(6));
            long bytes = parseBytes(m.group(7));
            long duration = m.group(8) == null ? -1L : Long.parseLong(m.group(8));
            return Optional.of(new LogEntry(
                    m.group(1),
                    timestamp,
                    m.group(4),
                    stripQuery(m.group(5)),
                    status,
                    bytes,
                    duration));
        } catch (DateTimeParseException | IllegalArgumentException e) {
            // NumberFormatException is an IllegalArgumentException, so the two arms
            // below cover a bad timestamp and every bad numeric or out of range field.
            // A line that matches the shape but carries impossible values is still a
            // malformed line as far as the report is concerned.
            return Optional.empty();
        }
    }

    /** Apache writes "-" when no body was sent. */
    private static long parseBytes(String field) {
        return "-".equals(field) ? 0L : Long.parseLong(field);
    }

    /**
     * Query strings are dropped so that /search?q=a and /search?q=b group together.
     * Without this the top endpoints list degenerates into one row per unique query.
     */
    private static String stripQuery(String path) {
        int q = path.indexOf('?');
        return q < 0 ? path : path.substring(0, q);
    }
}
