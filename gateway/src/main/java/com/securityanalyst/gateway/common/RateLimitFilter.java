package com.securityanalyst.gateway.common;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Per-IP-address rate limits, checked before anything else in the security chain, so a
 * flood is turned away as cheaply as possible.
 *
 * - Every request counts against a generous limit.
 * - Login and signup also count against a much stricter one: each runs the deliberately
 *   slow password hash, so they are the cheapest way to overload the server or guess passwords.
 *
 * The IP address is the connection's own (getRemoteAddr). An X-Forwarded-For header is
 * ignored: anyone can write one, so trusting it would let an attacker pick a fresh "IP"
 * for every request. When the gateway runs behind a proxy (step 17), the proxy is
 * configured as the only trusted source of that header.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    static final Set<String> CREDENTIAL_PATHS = Set.of("/api/auth/login", "/api/auth/signup");

    private final KeyedRateLimiter allRequests;
    private final KeyedRateLimiter credentialRequests;

    public RateLimitFilter(KeyedRateLimiter allRequests, KeyedRateLimiter credentialRequests) {
        this.allRequests = allRequests;
        this.credentialRequests = credentialRequests;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String client = request.getRemoteAddr();
        Duration wait = allRequests.tryAcquire(client);
        if (wait.isZero() && isCredentialRequest(request)) {
            wait = credentialRequests.tryAcquire(client);
        }
        if (!wait.isZero()) {
            response.setHeader("Retry-After", TooManyRequestsException.retryAfterHeader(wait));
            SecurityErrors.write(response, HttpStatus.TOO_MANY_REQUESTS, "Too many requests. Try again later.");
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean isCredentialRequest(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return "POST".equals(request.getMethod()) && CREDENTIAL_PATHS.contains(path);
    }
}
