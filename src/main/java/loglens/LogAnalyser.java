package loglens;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Reads a log file once and drives both the traffic report and the detector from
 * the same pass.
 *
 * <p>Deliberately streams line by line instead of {@code Files.readAllLines}. Access
 * logs are routinely larger than heap, and reading one into a list is the most
 * common way a working tool falls over the first time it meets production data.</p>
 */
public final class LogAnalyser {

    private final LogParser parser = new LogParser();
    private final DetectorConfig config;

    public LogAnalyser(DetectorConfig config) {
        this.config = config;
    }

    public Result analyse(Path file) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return analyse(reader);
        }
    }

    /** Package visible overload so tests can drive the analyser from a string without touching disk. */
    public Result analyse(BufferedReader reader) throws IOException {
        TrafficReport report = new TrafficReport();
        SuspiciousActivityDetector detector = new SuspiciousActivityDetector(config);

        String line;
        while ((line = reader.readLine()) != null) {
            Optional<LogEntry> parsed = parser.parse(line);
            if (parsed.isEmpty()) {
                report.recordMalformedLine();
                continue;
            }
            LogEntry entry = parsed.get();
            report.accept(entry);
            detector.accept(entry);
        }
        return new Result(report, detector.findings());
    }

    /** The two outputs of one pass over the file. */
    public record Result(TrafficReport report, java.util.List<Finding> findings) {
    }
}
