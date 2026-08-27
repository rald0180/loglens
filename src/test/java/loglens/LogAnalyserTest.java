package loglens;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class LogAnalyserTest {

    private LogAnalyser.Result analyse(String log) throws IOException {
        LogAnalyser analyser = new LogAnalyser(new DetectorConfig(3, Duration.ofSeconds(60), 3));
        return analyser.analyse(new BufferedReader(new StringReader(log)));
    }

    @Test
    void runsBothTheReportAndTheDetectorInOnePass() throws IOException {
        String log = """
                10.0.0.1 - - [12/Aug/2026:09:00:00 +1000] "GET /api/items HTTP/1.1" 200 512 8
                10.0.0.1 - - [12/Aug/2026:09:00:01 +1000] "GET /api/items HTTP/1.1" 200 512 12
                198.51.100.9 - - [12/Aug/2026:09:00:02 +1000] "POST /login HTTP/1.1" 401 0 4
                198.51.100.9 - - [12/Aug/2026:09:00:03 +1000] "POST /login HTTP/1.1" 401 0 4
                198.51.100.9 - - [12/Aug/2026:09:00:04 +1000] "POST /login HTTP/1.1" 401 0 4
                """;

        LogAnalyser.Result result = analyse(log);

        assertEquals(5, result.report().totalRequests());
        assertEquals(1, result.findings().size());
        assertEquals(Finding.Kind.CREDENTIAL_STUFFING, result.findings().get(0).kind());
    }

    @Test
    void oneBadLineDoesNotStopTheRestOfTheFileBeingRead() throws IOException {
        String log = """
                10.0.0.1 - - [12/Aug/2026:09:00:00 +1000] "GET /a HTTP/1.1" 200 10 1
                <<< truncated line from a rotated file
                10.0.0.1 - - [12/Aug/2026:09:00:02 +1000] "GET /b HTTP/1.1" 200 10 1
                """;

        LogAnalyser.Result result = analyse(log);

        assertEquals(2, result.report().totalRequests());
        assertEquals(1, result.report().malformedLines());
    }

    @Test
    void anEmptyFileIsNotAnError() throws IOException {
        LogAnalyser.Result result = analyse("");

        assertEquals(0, result.report().totalRequests());
        assertTrue(result.findings().isEmpty());
    }
}
