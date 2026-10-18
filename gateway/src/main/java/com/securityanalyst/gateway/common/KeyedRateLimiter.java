package com.securityanalyst.gateway.common;

import java.time.Duration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.TimeMeter;

/**
 * "At most N requests per minute" for each key (here: each client IP address).
 *
 * Each key gets a token bucket: it holds up to N tokens, every request takes one, and
 * tokens flow back in steadily (N per minute). A short burst is fine; a sustained flood
 * runs the bucket dry and is refused until tokens have refilled.
 *
 * The buckets live in a bounded cache, so a flood of made-up keys cannot fill the memory.
 * A bucket untouched for two minutes is dropped: by then it would be full again anyway,
 * so forgetting it changes nothing.
 */
public class KeyedRateLimiter {

    private final int perMinute;
    private final TimeMeter time;
    private final Cache<String, Bucket> buckets;

    public KeyedRateLimiter(int perMinute, int maxKeys) {
        this(perMinute, maxKeys, TimeMeter.SYSTEM_NANOTIME);
    }

    /** Tests pass a fake clock here. */
    KeyedRateLimiter(int perMinute, int maxKeys, TimeMeter time) {
        this.perMinute = perMinute;
        this.time = time;
        this.buckets = Caffeine.newBuilder()
                .maximumSize(maxKeys)
                .expireAfterAccess(Duration.ofMinutes(2))
                .build();
    }

    /**
     * Takes one token for this key.
     *
     * @return {@link Duration#ZERO} if the request may go ahead, otherwise how long until it would be allowed
     */
    public Duration tryAcquire(String key) {
        ConsumptionProbe probe = buckets.get(key, k -> newBucket()).tryConsumeAndReturnRemaining(1);
        return probe.isConsumed() ? Duration.ZERO : Duration.ofNanos(probe.getNanosToWaitForRefill());
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(limit -> limit.capacity(perMinute).refillGreedy(perMinute, Duration.ofMinutes(1)))
                .withCustomTimePrecision(time)
                .build();
    }
}
