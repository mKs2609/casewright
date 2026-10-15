package com.securityanalyst.gateway.common;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Refuses oversized request bodies before anything reads them, so nobody can
 * tie up the server (memory, CPU, password hashing) by sending megabytes.
 *
 * - Body larger than the limit (by its Content-Length header)  -> 413 Payload Too Large
 * - Body sent in chunks with no length given up front          -> 411 Length Required
 *   (its size cannot be checked before reading it; our clients never need this)
 */
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    private final long maxBytes;

    public RequestSizeLimitFilter(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String transferEncoding = request.getHeader("Transfer-Encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase().contains("chunked")) {
            SecurityErrors.write(response, HttpStatus.LENGTH_REQUIRED, "Request body must state its length");
            return;
        }
        if (request.getContentLengthLong() > maxBytes) {
            SecurityErrors.write(response, HttpStatus.PAYLOAD_TOO_LARGE, "Request body is too large");
            return;
        }
        chain.doFilter(request, response);
    }
}
