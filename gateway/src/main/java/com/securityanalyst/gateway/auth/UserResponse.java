package com.securityanalyst.gateway.auth;

/** What we tell a client about a user. Never includes the password hash. */
public record UserResponse(String username, Role role) {

    static UserResponse from(User user) {
        return new UserResponse(user.getUsername(), user.getRole());
    }
}
