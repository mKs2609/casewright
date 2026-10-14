package com.securityanalyst.gateway.common;

import org.springframework.http.HttpStatus;

/**
 * An error we are happy to show the caller: it carries the HTTP status and a
 * message written for them. Anything that is NOT an ApiException is treated as
 * an internal error and its details stay on the server.
 */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
