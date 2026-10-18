package com.securityanalyst.gateway.common;

import java.time.Duration;

import org.springframework.http.HttpStatus;

/** A request refused by a rate limit: 429, with a Retry-After header saying how long to wait. */
public class TooManyRequestsException extends ApiException {

    private final Duration retryAfter;

    public TooManyRequestsException(String message, Duration retryAfter) {
        super(HttpStatus.TOO_MANY_REQUESTS, message);
        this.retryAfter = retryAfter;
    }

    /** The Retry-After header value: whole seconds, rounded up, at least 1. */
    public String retryAfterHeader() {
        return retryAfterHeader(retryAfter);
    }

    static String retryAfterHeader(Duration wait) {
        long seconds = wait.toSeconds() + (wait.toNanosPart() > 0 ? 1 : 0);
        return Long.toString(Math.max(1, seconds));
    }
}
