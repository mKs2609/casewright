package com.securityanalyst.gateway.common;

import java.util.Map;
import java.util.TreeMap;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns exceptions into consistent JSON error responses.
 * Rule: say WHICH field is wrong and WHY, but never repeat the value that was sent.
 * (A catch-all for unexpected errors and trace IDs is added in a later step.)
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /** Errors we raised on purpose, e.g. "username already taken". */
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
        return ResponseEntity.badRequest().body(new ApiError("Validation failed", fields));
    }

    /** The body was not valid JSON, had the wrong types, or contained unknown fields. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiError.of("Request body is missing, malformed, or contains unknown fields"));
    }
}
