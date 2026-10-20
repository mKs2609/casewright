package com.securityanalyst.gateway.incident;

import java.time.OffsetDateTime;
import java.util.List;

import com.securityanalyst.gateway.common.IpAddress;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * A batch of login events for one account, e.g. a burst of failures from many addresses
 * (credential stuffing) or a success from an unusual country.
 */
public record LoginIncidentRequest(
        @NotNull(message = "is required")
        @Pattern(regexp = IDENTITY_PATTERN, message = IDENTITY_MESSAGE)
        String subjectIdentity,

        // @Valid: also check every event against the rules in LoginEvent below.
        @NotNull(message = "is required")
        @Size(min = 1, max = 500, message = "must contain 1-500 events")
        List<@NotNull(message = "must not be null") @Valid LoginEvent> events) implements IncidentRequest {

    /**
     * One login attempt.
     *
     * @param timestamp must include a time zone offset (e.g. 2026-10-19T08:15:00Z), so the
     *                  time is never ambiguous; a timestamp without one is refused
     * @param success   a Boolean, not a boolean, so that a missing value is an error rather
     *                  than silently becoming false
     */
    public record LoginEvent(
            @NotNull(message = "is required")
            @Pattern(regexp = IDENTITY_PATTERN, message = IDENTITY_MESSAGE)
            String username,

            @NotNull(message = "is required")
            @IpAddress
            String ip,

            @NotNull(message = "is required")
            OffsetDateTime timestamp,

            @NotNull(message = "is required")
            Boolean success,

            @NotNull(message = "is required")
            @Pattern(regexp = "^[A-Z]{2}$", message = "must be a two-letter country code such as IN")
            String country,

            @Size(max = 64, message = "must be at most 64 characters")
            @Pattern(regexp = "^[A-Za-z .'-]*$", message = "may only contain letters, spaces, dots, apostrophes and hyphens")
            String city,

            @Size(max = 300, message = "must be at most 300 characters")
            String userAgent) {
    }
}
