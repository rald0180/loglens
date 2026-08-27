package loglens;

import java.time.Duration;

/**
 * Thresholds for {@link SuspiciousActivityDetector}.
 *
 * <p>Kept as a separate value type rather than a pile of constructor arguments so
 * that tests can drive the detector with tight thresholds and small fixtures
 * instead of having to generate hundreds of lines.</p>
 *
 * @param authFailureThreshold how many 401 or 403 responses inside the window count as an attack
 * @param window               the sliding window those failures must fall inside
 * @param distinctNotFoundThreshold how many distinct missing paths count as scanning
 */
public record DetectorConfig(int authFailureThreshold, Duration window, int distinctNotFoundThreshold) {

    public DetectorConfig {
        if (authFailureThreshold < 1) {
            throw new IllegalArgumentException("authFailureThreshold must be at least 1");
        }
        if (distinctNotFoundThreshold < 1) {
            throw new IllegalArgumentException("distinctNotFoundThreshold must be at least 1");
        }
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
    }

    public static DetectorConfig defaults() {
        return new DetectorConfig(5, Duration.ofMinutes(1), 15);
    }
}
