package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.github.bucket4j.TimeMeter;

/** Plain unit test with a fake clock: no Spring, no waiting. */
class KeyedRateLimiterTest {

    /** A clock that only moves when the test says so. */
    static class FakeTime implements TimeMeter {
        private long nanos;

        void advance(Duration duration) {
            nanos += duration.toNanos();
        }

        @Override
        public long currentTimeNanos() {
            return nanos;
        }

        @Override
        public boolean isWallClockBased() {
            return false;
        }
    }

    private final FakeTime time = new FakeTime();
    private final KeyedRateLimiter limiter = new KeyedRateLimiter(6, 1000, time);   // 6 per minute

    @Test
    void allowsTheLimitThenRefusesAndSaysHowLongToWait() {
        for (int i = 0; i < 6; i++) {
            assertThat(limiter.tryAcquire("10.0.0.1")).isZero();
        }

        // Tokens come back at 6 per minute, so one every 10 seconds.
        assertThat(limiter.tryAcquire("10.0.0.1")).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void tokensFlowBackOverTime() {
        for (int i = 0; i < 6; i++) {
            limiter.tryAcquire("10.0.0.1");
        }

        time.advance(Duration.ofSeconds(10));
        assertThat(limiter.tryAcquire("10.0.0.1")).isZero();
        assertThat(limiter.tryAcquire("10.0.0.1")).isPositive();

        time.advance(Duration.ofMinutes(1));
        for (int i = 0; i < 6; i++) {
            assertThat(limiter.tryAcquire("10.0.0.1")).isZero();
        }
    }

    @Test
    void eachAddressHasItsOwnBucket() {
        for (int i = 0; i < 6; i++) {
            limiter.tryAcquire("10.0.0.1");
        }

        assertThat(limiter.tryAcquire("10.0.0.1")).isPositive();
        assertThat(limiter.tryAcquire("10.0.0.2")).isZero();
    }

    @Test
    void retryAfterIsWholeSecondsRoundedUpAndAtLeastOne() {
        assertThat(TooManyRequestsException.retryAfterHeader(Duration.ofSeconds(10))).isEqualTo("10");
        assertThat(TooManyRequestsException.retryAfterHeader(Duration.ofMillis(9_001))).isEqualTo("10");
        assertThat(TooManyRequestsException.retryAfterHeader(Duration.ofMillis(1))).isEqualTo("1");
    }
}
