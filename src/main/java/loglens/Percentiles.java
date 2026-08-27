package loglens;

import java.util.Arrays;

/**
 * Percentile calculation over request durations.
 *
 * <p>Uses the nearest rank method: the p-th percentile is the value at index
 * ceil(p/100 * n) - 1 of the sorted sample. Nearest rank always returns a value
 * that actually occurred in the data, which matters for latency reporting.
 * An interpolated percentile can report a p99 that no single request ever hit,
 * which is misleading when the number you are chasing is a real slow request.</p>
 */
public final class Percentiles {

    private final long[] sorted;

    /** Takes a defensive copy so later mutation of the caller's array cannot corrupt results. */
    public Percentiles(long[] samples) {
        this.sorted = samples.clone();
        Arrays.sort(this.sorted);
    }

    public boolean isEmpty() {
        return sorted.length == 0;
    }

    public int size() {
        return sorted.length;
    }

    /**
     * @param p percentile in the range 0 to 100
     * @return the sample at that percentile, or -1 when there are no samples
     */
    public long at(double p) {
        if (p < 0 || p > 100) {
            throw new IllegalArgumentException("percentile must be between 0 and 100, got " + p);
        }
        if (isEmpty()) {
            return -1L;
        }
        int rank = (int) Math.ceil(p / 100.0 * sorted.length);
        int index = Math.max(0, Math.min(sorted.length - 1, rank - 1));
        return sorted[index];
    }

    public long max() {
        return isEmpty() ? -1L : sorted[sorted.length - 1];
    }
}
