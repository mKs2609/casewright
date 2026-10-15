package com.securityanalyst.gateway.common;

import org.slf4j.MDC;

/**
 * The trace ID of the request currently being handled.
 *
 * Every request gets a random ID (see TraceIdFilter). It is sent back in the
 * X-Trace-Id header and in every error body, and it is printed on every log
 * line written while handling that request. So "my request failed, trace ID
 * 3f9a..." leads straight to the matching lines in the server log.
 *
 * MDC ("mapped diagnostic context") is the logging library's per-request
 * notepad: whatever is put there appears in log lines from the same request.
 */
public final class TraceIds {

    public static final String HEADER = "X-Trace-Id";
    static final String MDC_KEY = "traceId";

    private TraceIds() {
    }

    /** The current request's trace ID, or null outside a request. */
    public static String current() {
        return MDC.get(MDC_KEY);
    }
}
