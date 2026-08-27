package loglens;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PercentilesTest {

    @Test
    void nearestRankReturnsAValueThatActuallyOccurred() {
        Percentiles p = new Percentiles(new long[]{10, 20, 30, 40, 50, 60, 70, 80, 90, 100});

        assertEquals(50L, p.at(50));
        assertEquals(90L, p.at(90));
        assertEquals(100L, p.at(99));
        assertEquals(100L, p.max());
    }

    @Test
    void handlesASingleSample() {
        Percentiles p = new Percentiles(new long[]{42});

        assertEquals(42L, p.at(0));
        assertEquals(42L, p.at(50));
        assertEquals(42L, p.at(100));
    }

    @Test
    void emptySampleReportsMinusOneRatherThanThrowing() {
        Percentiles p = new Percentiles(new long[]{});

        assertTrue(p.isEmpty());
        assertEquals(-1L, p.at(95));
        assertEquals(-1L, p.max());
    }

    @Test
    void sortsUnsortedInput() {
        Percentiles p = new Percentiles(new long[]{90, 10, 50, 30, 70});

        assertEquals(50L, p.at(50));
        assertEquals(90L, p.max());
    }

    @Test
    void doesNotMutateTheCallersArray() {
        long[] samples = {30, 10, 20};
        new Percentiles(samples);

        assertArrayEquals(new long[]{30, 10, 20}, samples);
    }

    @Test
    void rejectsAPercentileOutsideZeroToOneHundred() {
        Percentiles p = new Percentiles(new long[]{1, 2, 3});

        assertThrows(IllegalArgumentException.class, () -> p.at(-1));
        assertThrows(IllegalArgumentException.class, () -> p.at(101));
    }
}
