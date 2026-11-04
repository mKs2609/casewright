package com.securityanalyst.gateway.live;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * Limits for the live feed, from the {@code live.*} settings (ADR-49).
 *
 * @param maxConnectionsPerUser open feeds one user may have (one per dashboard tab)
 * @param maxConnections        open feeds in total, so they cannot use up the server
 * @param heartbeatInterval     how often an idle feed sends a keep-alive line; a feed whose browser
 *                              has gone is noticed when that write fails
 * @param maxPendingChanges     changed incidents queued for one feed; a feed further behind than this
 *                              is closed, and the dashboard reconnects and reloads
 */
@ConfigurationProperties("live")
@Validated
public record LiveProperties(
        @Min(1) int maxConnectionsPerUser,
        @Min(1) int maxConnections,
        @NotNull Duration heartbeatInterval,
        @Min(1) int maxPendingChanges) {
}
