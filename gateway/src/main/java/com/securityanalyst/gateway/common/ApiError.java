package com.securityanalyst.gateway.common;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The one shape every error response has.
 * {@code fields} is only present for validation errors: field name -> what is wrong with it.
 * {@code traceId} matches the X-Trace-Id header and the server log lines for this request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(String error, Map<String, String> fields, String traceId) {

    public static ApiError of(String error) {
        return new ApiError(error, null, TraceIds.current());
    }

    public static ApiError withFields(String error, Map<String, String> fields) {
        return new ApiError(error, fields, TraceIds.current());
    }
}
