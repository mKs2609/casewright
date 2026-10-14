package com.securityanalyst.gateway.auth;

/** Who is making the current request, as proven by a valid access token. */
public record AuthenticatedUser(Long id, String username, Role role) {
}
