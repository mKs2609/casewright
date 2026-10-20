package com.securityanalyst.gateway.incident;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * A suspicious phone call, e.g. someone claiming to be IT support and asking for a
 * one-time code (voice phishing, "vishing"). The transcript is kept exactly as sent.
 */
public record CallTranscriptIncidentRequest(
        @NotNull(message = "is required")
        @Pattern(regexp = IDENTITY_PATTERN, message = IDENTITY_MESSAGE)
        String subjectIdentity,

        // 6-15 digits with an optional leading +, e.g. +15555550142. No spaces or dashes.
        @NotNull(message = "is required")
        @Pattern(regexp = "^\\+?[0-9]{6,15}$", message = "must be a phone number: 6-15 digits, optionally starting with +")
        String callerNumber,

        @NotNull(message = "is required")
        @Size(min = 1, max = 20_000, message = "must be 1-20000 characters")
        String transcript) implements IncidentRequest {
}
