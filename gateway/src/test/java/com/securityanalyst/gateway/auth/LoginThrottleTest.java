package com.securityanalyst.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import com.securityanalyst.gateway.common.RateLimitProperties;

/** Plain unit test with a fake clock: no Spring, no waiting. */
class LoginThrottleTest {

    /** A clock that only moves when the test says so. */
    static class FakeClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private final FakeClock clock = new FakeClock();

    private LoginThrottle throttle(int freeAttempts, Duration maxBackoff) {
        RateLimitProperties limits = new RateLimitProperties(100, 10, freeAttempts, maxBackoff, Duration.ofHours(1), 1000);
        return new LoginThrottle(limits, clock);
    }

    @Test
    void theFirstAttemptsAreFreeThenTheWaitDoubles() {
        LoginThrottle throttle = throttle(3, Duration.ofMinutes(15));

        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofSeconds(1));

        clock.advance(Duration.ofSeconds(1));
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofSeconds(2));

        clock.advance(Duration.ofSeconds(2));
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofSeconds(4));
    }

    @Test
    void aRefusedAttemptIsNotCountedAndReportsTheTimeLeft() {
        LoginThrottle throttle = throttle(1, Duration.ofMinutes(15));
        throttle.tryAttempt("asha.rao");                       // free; the next one waits 1 s
        clock.advance(Duration.ofSeconds(1));
        throttle.tryAttempt("asha.rao");                       // allowed; the next one waits 2 s

        clock.advance(Duration.ofMillis(500));
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofMillis(1500));
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofMillis(1500));

        // The refusals above did not make things worse: after the wait, the next step is 4 s, not more.
        clock.advance(Duration.ofMillis(1500));
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isEqualTo(Duration.ofSeconds(4));
    }

    @Test
    void theWaitNeverGrowsBeyondTheMaximumSoThereIsNoPermanentLockout() {
        LoginThrottle throttle = throttle(5, Duration.ofMinutes(15));

        assertThat(throttle.backoffAfter(4)).isZero();
        assertThat(throttle.backoffAfter(5)).isEqualTo(Duration.ofSeconds(1));
        assertThat(throttle.backoffAfter(14)).isEqualTo(Duration.ofSeconds(512));
        assertThat(throttle.backoffAfter(15)).isEqualTo(Duration.ofMinutes(15));
        assertThat(throttle.backoffAfter(1_000_000)).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void aSuccessfulLoginStartsTheCountAgain() {
        LoginThrottle throttle = throttle(2, Duration.ofMinutes(15));
        throttle.tryAttempt("asha.rao");
        throttle.tryAttempt("asha.rao");
        assertThat(throttle.tryAttempt("asha.rao")).isPositive();

        throttle.succeeded("asha.rao");

        assertThat(throttle.tryAttempt("asha.rao")).isZero();
        assertThat(throttle.tryAttempt("asha.rao")).isZero();
    }

    @Test
    void eachUsernameHasItsOwnCount() {
        LoginThrottle throttle = throttle(1, Duration.ofMinutes(15));
        throttle.tryAttempt("asha.rao");

        assertThat(throttle.tryAttempt("asha.rao")).isPositive();
        assertThat(throttle.tryAttempt("ravi.k")).isZero();
    }

    @Test
    void forgettingAttemptsBeforeTheLongestWaitIsRefusedAtStartup() {
        RateLimitProperties nonsense = new RateLimitProperties(100, 10, 5, Duration.ofHours(2), Duration.ofHours(1), 1000);

        assertThatThrownBy(() -> new LoginThrottle(nonsense, clock)).isInstanceOf(IllegalArgumentException.class);
    }
}
