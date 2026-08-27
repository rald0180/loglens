package loglens;

import java.time.Instant;
import java.util.Objects;

/**
 * One parsed line of an access log.
 *
 * <p>Immutable by design. Once a line has been parsed and validated there is no
 * legitimate reason for any later stage of the pipeline to change it, so making
 * the type immutable removes a whole class of bug from the report builders.</p>
 *
 * @param clientIp     the client address the request came from
 * @param timestamp    when the server finished handling the request
 * @param method       HTTP method, upper case
 * @param path         request path, query string stripped
 * @param status       HTTP status code
 * @param bytesSent    response body size in bytes, 0 when the server logged "-"
 * @param durationMs   how long the request took, or -1 when the log does not record it
 */
public record LogEntry(
        String clientIp,
        Instant timestamp,
        String method,
        String path,
        int status,
        long bytesSent,
        long durationMs) {

    public LogEntry {
        Objects.requireNonNull(clientIp, "clientIp");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        if (clientIp.isBlank()) {
            throw new IllegalArgumentException("clientIp must not be blank");
        }
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("status out of range: " + status);
        }
        if (bytesSent < 0) {
            throw new IllegalArgumentException("bytesSent must not be negative: " + bytesSent);
        }
    }

    /** True for 4xx and 5xx responses. */
    public boolean isError() {
        return status >= 400;
    }

    /** True for the two statuses that indicate a rejected credential. */
    public boolean isAuthFailure() {
        return status == 401 || status == 403;
    }

    public boolean isNotFound() {
        return status == 404;
    }

    public boolean hasDuration() {
        return durationMs >= 0;
    }
}
