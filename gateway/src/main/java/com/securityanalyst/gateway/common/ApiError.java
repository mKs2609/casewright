package com.securityanalyst.gateway.common;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The one shape every error response has.
 * {@code fields} is only present for validation errors: field name -> what is wrong with it.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(String error, Map<String, String> fields) {

    public static ApiError of(String error) {
        return new ApiError(error, null);
    }
}
