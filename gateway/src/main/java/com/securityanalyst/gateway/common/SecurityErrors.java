package com.securityanalyst.gateway.common;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes the standard {"error": ..., "traceId": ...} body for requests refused
 * by filters, which run before any controller (so ApiExceptionHandler never sees them).
 * Messages are fixed text chosen by us; never pass request data in here.
 */
public final class SecurityErrors {

    private SecurityErrors() {
    }

    public static void write(HttpServletResponse response, HttpStatus status, String fixedMessage) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String traceId = TraceIds.current();
        String body = "{\"error\":\"" + fixedMessage + "\""
                + (traceId == null ? "" : ",\"traceId\":\"" + traceId + "\"")
                + "}";
        response.getWriter().write(body);
    }
}
