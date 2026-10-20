package com.securityanalyst.gateway.common;

import java.util.Map;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import tools.jackson.databind.exc.InvalidTypeIdException;

/**
 * Turns exceptions into consistent JSON error responses.
 * Rules: say WHICH field is wrong and WHY, but never repeat the value that was
 * sent; never send internal details (stack traces, SQL, class names) to the
 * caller; always include the trace ID.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** Errors we raised on purpose, e.g. "username already taken". */
    /** Rate limits: also tell the caller how long to wait. */
    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiError> handleTooManyRequests(TooManyRequestsException e) {
        return ResponseEntity.status(e.getStatus())
                .header("Retry-After", e.retryAfterHeader())
                .body(ApiError.of(e.getMessage()));
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApiException(ApiException e) {
        return ResponseEntity.status(e.getStatus()).body(ApiError.of(e.getMessage()));
    }

    /** A request body broke a rule declared on a request record (@Size, @Pattern, ...). */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException e) {
        Map<String, String> fields = new TreeMap<>();
        for (FieldError fieldError : e.getBindingResult().getFieldErrors()) {
            fields.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(ApiError.withFields("Validation failed", fields));
    }

    /** The body was not valid JSON, had the wrong types, or contained unknown fields. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException e) {
        // A body whose "kind" field is missing or not one we know (e.g. POST /api/incidents).
        // The message is fixed text: the rejected value is never echoed back.
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof InvalidTypeIdException) {
                return ResponseEntity.badRequest().body(
                        ApiError.withFields("Validation failed", Map.of("kind", "is missing or not a known kind")));
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiError.of("Request body is missing, malformed, or contains unknown fields"));
    }

    /** A value in the URL had the wrong type, e.g. /users/abc where a number is expected. */
    @ExceptionHandler(TypeMismatchException.class)
    public ResponseEntity<ApiError> handleTypeMismatch(TypeMismatchException e) {
        return ResponseEntity.badRequest().body(ApiError.of("A value in the request has the wrong type"));
    }

    /**
     * Everything else.
     *
     * - Security refusals are handed back to Spring Security, which answers 401 / 403.
     * - Errors Spring raises itself (no such URL, wrong HTTP method, unsupported
     *   content type...) keep their real status code, with a short generic message.
     * - Anything truly unexpected becomes a 500. The caller gets only a generic
     *   message and the trace ID; the full stack trace goes to the server log.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleEverythingElse(Exception e) throws Exception {
        if (e instanceof AccessDeniedException || e instanceof AuthenticationException) {
            throw e;
        }
        if (e instanceof ErrorResponse frameworkError) {
            HttpStatusCode status = frameworkError.getStatusCode();
            HttpStatus known = HttpStatus.resolve(status.value());
            String message = known != null ? known.getReasonPhrase() : "Request could not be processed";
            return ResponseEntity.status(status).headers(frameworkError.getHeaders()).body(ApiError.of(message));
        }
        log.error("Unexpected error while handling a request", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiError.of("Something went wrong on our side. If it keeps happening, report the trace ID."));
    }
}
