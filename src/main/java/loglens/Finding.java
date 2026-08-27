package loglens;

import java.time.Instant;

/**
 * One piece of suspicious client behaviour worth a human look.
 *
 * @param kind        what pattern was matched
 * @param clientIp    the client responsible
 * @param count       how many requests triggered it
 * @param firstSeen   timestamp of the first request in the matched group
 * @param lastSeen    timestamp of the last request in the matched group
 * @param detail      a short human readable explanation
 */
public record Finding(
        Kind kind,
        String clientIp,
        int count,
        Instant firstSeen,
        Instant lastSeen,
        String detail) {

    public enum Kind {
        /** Repeated rejected credentials from one address inside a short window. */
        CREDENTIAL_STUFFING,
        /** One address probing many different paths that do not exist. */
        PATH_SCANNING
    }
}
