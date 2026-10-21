package com.securityanalyst.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.test.web.servlet.ResultMatcher;

/**
 * Checks that an error response does not repeat a rejected value back.
 *
 * Every error body carries a random trace ID made of hex characters (0-9, a-f), e.g.
 * "traceId":"92aec04c192e4713". A short rejected value made of those characters, such as
 * "ab", turns up inside a random trace ID about once in 17 runs, which made a plain
 * "body does not contain ..." check fail at random. So the trace ID is blanked out first.
 */
public final class NoEcho {

    private NoEcho() {
    }

    /** The body with its trace ID replaced by "*", so it can be compared or searched safely. */
    public static String withoutTraceId(String json) {
        return json.replaceAll("\"traceId\":\"[0-9a-f]{16}\"", "\"traceId\":\"*\"");
    }

    /** Use as {@code .andExpect(doesNotEcho(value))}. */
    public static ResultMatcher doesNotEcho(String rejectedValue) {
        return result -> assertThat(withoutTraceId(result.getResponse().getContentAsString()))
                .as("the response must not repeat the rejected value back")
                .doesNotContain(rejectedValue);
    }
}
