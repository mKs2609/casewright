package com.securityanalyst.gateway.common;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * Rate-limit thresholds, from the {@code security.rate-limit.*} settings in
 * application.properties. The application refuses to start if one is missing or nonsensical.
 *
 * @param requestsPerMinute          any request, per client IP address
 * @param credentialRequestsPerMinute login and signup (they run the slow password hash), per client IP address
 * @param freeLoginAttempts          login attempts per username before each further attempt has to wait
 * @param maxLoginBackoff            the longest wait between login attempts (it doubles up to this)
 * @param forgetLoginAttemptsAfter   a username's failed attempts are forgotten after this long without one
 * @param maxTrackedClients          upper bound on IP addresses / usernames held in memory at once
 */
@ConfigurationProperties("security.rate-limit")
@Validated
public record RateLimitProperties(
        @Min(1) int requestsPerMinute,
        @Min(1) int credentialRequestsPerMinute,
        @Min(1) int freeLoginAttempts,
        @NotNull Duration maxLoginBackoff,
        @NotNull Duration forgetLoginAttemptsAfter,
        @Min(1) int maxTrackedClients) {
}
