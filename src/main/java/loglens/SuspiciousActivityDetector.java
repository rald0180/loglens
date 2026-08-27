package loglens;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Flags two client behaviours that are cheap to detect and usually worth a look:
 * repeated rejected credentials, and probing for paths that do not exist.
 *
 * <p>Both run in a single pass. Entries are fed in as they are parsed and nothing
 * holds the whole log in memory, so the cost is bounded by the number of distinct
 * client addresses rather than the size of the file.</p>
 *
 * <p>Credential stuffing uses a sliding window per address, held as an
 * {@link ArrayDeque} of failure timestamps. Each new failure evicts everything
 * older than the window from the head, then the remaining size is compared to the
 * threshold. Both ends of a deque are O(1), so the whole check is O(1) amortised
 * per failure. A plain list would make eviction O(n) and a sorted structure would
 * be wasted work, since log lines already arrive in time order.</p>
 *
 * <p>The detector assumes entries arrive in non decreasing timestamp order, which
 * holds for a single access log. An out of order entry is not a crash, it just
 * means the window for that address is evaluated against the newest timestamp seen.</p>
 */
public final class SuspiciousActivityDetector {

    private final DetectorConfig config;
    private final Map<String, Deque<Instant>> authFailures = new HashMap<>();
    private final Map<String, Set<String>> missingPaths = new HashMap<>();
    private final Map<String, Instant> firstNotFoundSeen = new HashMap<>();
    private final Map<String, Instant> lastNotFoundSeen = new HashMap<>();
    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> alreadyReported = new HashSet<>();

    public SuspiciousActivityDetector(DetectorConfig config) {
        this.config = config;
    }

    /** Feed one entry into the detector. */
    public void accept(LogEntry entry) {
        if (entry.isAuthFailure()) {
            recordAuthFailure(entry);
        } else if (entry.isNotFound()) {
            recordMissingPath(entry);
        }
    }

    private void recordAuthFailure(LogEntry entry) {
        Deque<Instant> window = authFailures.computeIfAbsent(entry.clientIp(), ip -> new ArrayDeque<>());
        window.addLast(entry.timestamp());

        Instant cutoff = entry.timestamp().minus(config.window());
        while (!window.isEmpty() && window.peekFirst().isBefore(cutoff)) {
            window.removeFirst();
        }

        if (window.size() >= config.authFailureThreshold()) {
            String key = Finding.Kind.CREDENTIAL_STUFFING + ":" + entry.clientIp();
            if (alreadyReported.add(key)) {
                findings.add(new Finding(
                        Finding.Kind.CREDENTIAL_STUFFING,
                        entry.clientIp(),
                        window.size(),
                        window.peekFirst(),
                        window.peekLast(),
                        window.size() + " rejected credentials within " + config.window().toSeconds() + "s"));
            }
        }
    }

    private void recordMissingPath(LogEntry entry) {
        String ip = entry.clientIp();
        Set<String> paths = missingPaths.computeIfAbsent(ip, k -> new HashSet<>());
        paths.add(entry.path());
        firstNotFoundSeen.putIfAbsent(ip, entry.timestamp());
        lastNotFoundSeen.put(ip, entry.timestamp());

        if (paths.size() >= config.distinctNotFoundThreshold()) {
            String key = Finding.Kind.PATH_SCANNING + ":" + ip;
            if (alreadyReported.add(key)) {
                findings.add(new Finding(
                        Finding.Kind.PATH_SCANNING,
                        ip,
                        paths.size(),
                        firstNotFoundSeen.get(ip),
                        lastNotFoundSeen.get(ip),
                        paths.size() + " distinct missing paths requested"));
            }
        }
    }

    /** @return the findings in the order they were first detected */
    public List<Finding> findings() {
        return List.copyOf(findings);
    }
}
