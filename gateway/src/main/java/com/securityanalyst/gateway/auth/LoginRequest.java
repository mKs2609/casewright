package com.securityanalyst.gateway.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The JSON body of POST /api/auth/login. Only size limits here: whether the
 * username looks valid or exists is not revealed before the password check.
 */
public record LoginRequest(
        @NotBlank(message = "is required")
        @Size(max = 32, message = "is too long")
        String username,

        @NotBlank(message = "is required")
        @Size(max = 128, message = "is too long")
        String password) {

    @Override
    public String toString() {
        return "LoginRequest[username=" + username + ", password=<hidden>]";
    }
}
