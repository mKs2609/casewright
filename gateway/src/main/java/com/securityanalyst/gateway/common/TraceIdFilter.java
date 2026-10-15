package com.securityanalyst.gateway.common;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Gives every request a fresh random trace ID, before anything else runs.
 *
 * The ID is always generated here, never taken from the request: an ID chosen
 * by the caller could be used to forge or confuse log entries.
 */
public class TraceIdFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String traceId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        MDC.put(TraceIds.MDC_KEY, traceId);
        response.setHeader(TraceIds.HEADER, traceId);
        try {
            chain.doFilter(request, response);
        } finally {
            // Threads are reused for other requests, so the notepad must be wiped.
            MDC.remove(TraceIds.MDC_KEY);
        }
    }
}
