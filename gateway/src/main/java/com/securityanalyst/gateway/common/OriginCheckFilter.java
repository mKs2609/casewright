package com.securityanalyst.gateway.common;

import java.io.IOException;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Defence against cross-site request forgery (CSRF).
 *
 * The problem: browsers attach our cookies automatically, so a malicious
 * website could make a logged-in user's browser send us a request.
 * The defence: browsers also say where a request came from (the Origin and
 * Sec-Fetch-Site headers, which page scripts cannot fake). Any request that
 * changes something and comes from a website we don't know is refused.
 *
 * Tools like curl send neither header and are let through: they don't hold a
 * victim's cookies, so they are not a CSRF risk.
 * SameSite=Strict cookies are a second, independent layer of the same defence.
 */
public class OriginCheckFilter extends OncePerRequestFilter {

    private static final Set<String> READ_ONLY_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final Set<String> allowedOrigins;

    public OriginCheckFilter(Set<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!READ_ONLY_METHODS.contains(request.getMethod()) && isCrossSite(request)) {
            SecurityErrors.write(response, HttpStatus.FORBIDDEN, "Cross-site request refused");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isCrossSite(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin != null && !allowedOrigins.contains(origin)) {
            return true;
        }
        return "cross-site".equals(request.getHeader("Sec-Fetch-Site"));
    }
}
