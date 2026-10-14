package com.securityanalyst.gateway.auth;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * The JSON body of POST /api/auth/signup. There is deliberately no "role"
 * field: nobody chooses their own role.
 */
public record SignupRequest(
        @NotNull(message = "is required")
        @Pattern(regexp = "^[a-z0-9._-]{3,32}$",
                message = "must be 3-32 characters: lowercase letters, digits, dot, underscore or hyphen")
        String username,

        @NotNull(message = "is required")
        @Size(min = 12, max = 128, message = "must be 12-128 characters")
        String password) {

    /** Records print all their fields by default. Never let a password reach a log. */
    @Override
    public String toString() {
        return "SignupRequest[username=" + username + ", password=<hidden>]";
    }
}
