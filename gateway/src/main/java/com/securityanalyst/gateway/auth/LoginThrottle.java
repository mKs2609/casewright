package com.securityanalyst.gateway.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.securityanalyst.gateway.common.RateLimitProperties;

/**
 * Slows down password guessing against one account, from any number of IP addresses.
 *
 * The first few attempts on a username are free. After that, each attempt must wait
 * before the next is allowed, and the wait doubles every time (1 s, 2 s, 4 s, ...) up to a
 * maximum. There is no hard lockout: once the wait is over, the right password works,
 * so an attacker can slow the real user down but never lock them out for good.
 *
 * Details that matter:
 * - The check happens BEFORE the password is checked, so a waiting attacker learns nothing.
 * - Usernames that don't exist are treated exactly the same, so the answer doesn't reveal
 *   which accounts exist.
 * - An attempt is counted when it starts and cleared only when it succeeds. Counting after
 *   a failure instead would let a burst of parallel guesses all slip through before the
 *   first failure was recorded.
 * - Counters live in a bounded cache, so made-up usernames cannot fill the memory.
 */
@Component
public class LoginThrottle {

    /** Attempts since the last success, and the earliest moment the next one is allowed. */
    private record Attempts(int count, Instant nextAllowed) {
    }

    private final int freeAttempts;
    private final Duration maxBackoff;
    private final Clock clock;
    private final Cache<String, Attempts> attempts;

    @Autowired
    public LoginThrottle(RateLimitProperties limits) {
        this(limits, Clock.systemUTC());
    }

    /** Tests pass a fake clock here. */
    LoginThrottle(RateLimitProperties limits, Clock clock) {
        if (limits.forgetLoginAttemptsAfter().compareTo(limits.maxLoginBackoff()) <= 0) {
            throw new IllegalArgumentException(
                    "security.rate-limit.forget-login-attempts-after must be longer than max-login-backoff");
        }
        this.freeAttempts = limits.freeLoginAttempts();
        this.maxBackoff = limits.maxLoginBackoff();
        this.clock = clock;
        this.attempts = Caffeine.newBuilder()
                .maximumSize(limits.maxTrackedClients())
                .expireAfterWrite(limits.forgetLoginAttemptsAfter())
                .build();
    }

    /**
     * Call before checking the password.
     *
     * @return {@link Duration#ZERO} if the attempt may go ahead (it is now counted),
     *         otherwise how long to wait (the attempt is refused and not counted)
     */
    public Duration tryAttempt(String username) {
        Instant now = clock.instant();
        Duration[] wait = { Duration.ZERO };
        attempts.asMap().compute(username, (name, previous) -> {
            if (previous != null && now.isBefore(previous.nextAllowed())) {
                wait[0] = Duration.between(now, previous.nextAllowed());
                return previous;
            }
            int count = previous == null ? 1 : previous.count() + 1;
            return new Attempts(count, now.plus(backoffAfter(count)));
        });
        return wait[0];
    }

    /** Call after a correct password: the username starts again with its free attempts. */
    public void succeeded(String username) {
        attempts.invalidate(username);
    }

    /** Wait after this many attempts without a success: none at first, then 1 s doubling to the maximum. */
    Duration backoffAfter(int count) {
        if (count < freeAttempts) {
            return Duration.ZERO;
        }
        int doublings = Math.min(count - freeAttempts, 30);
        Duration wait = Duration.ofSeconds(1L << doublings);
        return wait.compareTo(maxBackoff) > 0 ? maxBackoff : wait;
    }
}
