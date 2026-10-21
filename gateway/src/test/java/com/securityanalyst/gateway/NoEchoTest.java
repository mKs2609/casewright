package com.securityanalyst.gateway;

import static com.securityanalyst.gateway.NoEcho.doesNotEcho;
import static com.securityanalyst.gateway.NoEcho.withoutTraceId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MvcResult;

/** The helper itself: not fooled by a lucky trace ID, but still catches a real echo. */
class NoEchoTest {

    private static MvcResult responseWithBody(String body) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.getWriter().write(body);
        MvcResult result = mock(MvcResult.class);
        when(result.getResponse()).thenReturn(response);
        return result;
    }

    // The exact bad luck that failed CI: the random trace ID happened to contain "ab".
    private static final String LUCKY_TRACE_ID =
            "{\"error\":\"Validation failed\",\"fields\":{\"username\":\"must be 3-32 characters\"},\"traceId\":\"3f09ab7c11e04d2a\"}";

    @Test
    void aValueThatOnlyAppearsInsideTheTraceIdIsNotAnEcho() throws Exception {
        assertThat(LUCKY_TRACE_ID).contains("ab");                       // the old check would have failed here
        assertThat(withoutTraceId(LUCKY_TRACE_ID)).doesNotContain("ab");

        doesNotEcho("ab").match(responseWithBody(LUCKY_TRACE_ID));     // passes
    }

    @Test
    void aValueThatReallyIsEchoedIsStillCaught() throws Exception {
        String echoed = "{\"error\":\"Username ab is invalid\",\"traceId\":\"3f09ab7c11e04d2a\"}";

        assertThatThrownBy(() -> doesNotEcho("ab").match(responseWithBody(echoed)))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("must not repeat the rejected value");
    }
}
