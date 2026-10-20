package com.securityanalyst.gateway.incident;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * A suspicious email someone reported, e.g. a possible phishing message.
 *
 * Text fields are limited in length but never "cleaned": whatever the attacker wrote is
 * kept exactly, because it is the evidence. It is only ever treated as data, never as code.
 */
public record EmailIncidentRequest(
        @NotNull(message = "is required")
        @Pattern(regexp = IDENTITY_PATTERN, message = IDENTITY_MESSAGE)
        String subjectIdentity,

        @NotNull(message = "is required")
        @Size(max = 254, message = "must be at most 254 characters")
        @Pattern(regexp = EMAIL_PATTERN, message = "must be an email address")
        String sender,

        // Optional: a "reply to" address different from the sender is a classic phishing sign.
        @Size(max = 254, message = "must be at most 254 characters")
        @Pattern(regexp = EMAIL_PATTERN, message = "must be an email address")
        String replyTo,

        @NotNull(message = "is required")
        @Size(max = 300, message = "must be at most 300 characters")
        String subject,

        @NotNull(message = "is required")
        @Size(min = 1, max = 20_000, message = "must be 1-20000 characters")
        String body) implements IncidentRequest {

    /** A plain email address: local part, @, domain with a dot. No display names, no comments. */
    static final String EMAIL_PATTERN = "^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,185}\\.[A-Za-z]{2,24}$";
}
