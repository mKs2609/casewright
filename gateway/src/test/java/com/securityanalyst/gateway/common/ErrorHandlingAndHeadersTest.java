package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jayway.jsonpath.JsonPath;
import com.securityanalyst.gateway.auth.JwtService;
import com.securityanalyst.gateway.health.HealthController;

/**
 * Error handling, trace IDs, security headers and the request size limit.
 * Runs the web layer with the real security configuration and filters.
 * {@code @WithMockUser} stands in for a logged-in user where one is needed.
 */
@WebMvcTest(HealthController.class)
@Import({ SecurityConfig.class, WebFilterConfig.class, ErrorHandlingAndHeadersTest.TestOnlyController.class })
@ExtendWith(OutputCaptureExtension.class)
class ErrorHandlingAndHeadersTest {

    private static final String SECRET_DETAIL = "password=hunter2 at db-internal-7:5432";

    /** Only exists in this test. Its endpoints misbehave on purpose. */
    @TestComponent
    @RestController
    static class TestOnlyController {

        @GetMapping("/api/test/crash")
        String crash() {
            throw new IllegalStateException("Connection failed: " + SECRET_DETAIL);
        }

        @GetMapping("/api/test/items/{id}")
        String item(@PathVariable Long id) {
            return "item " + id;
        }

        @PostMapping("/api/test/echo")
        String echo(@RequestBody String body) {
            return "received " + body.length() + " characters";
        }
    }

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private JdbcTemplate jdbc;

    @MockitoBean
    private JwtService jwtService;

    @BeforeEach
    void databaseIsUp() {
        when(jdbc.queryForObject("SELECT 1", Integer.class)).thenReturn(1);
    }

    private static String bodyTraceId(MockHttpServletResponse response) throws Exception {
        return JsonPath.read(response.getContentAsString(), "$.traceId");
    }

    // ------------------------------------------------------------------ unexpected errors

    @Test
    @WithMockUser
    void anUnexpectedErrorGivesA500WithATraceIdAndNoInternalDetails(CapturedOutput serverLog) throws Exception {
        MockHttpServletResponse response = mvc.perform(get("/api/test/crash"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value(containsString("Something went wrong")))
                .andExpect(content().string(not(containsString("hunter2"))))
                .andExpect(content().string(not(containsString("IllegalStateException"))))
                .andExpect(content().string(not(containsString("at com."))))
                .andReturn().getResponse();

        String traceId = bodyTraceId(response);
        assertThat(traceId).hasSize(16).isEqualTo(response.getHeader(TraceIds.HEADER));
        // The details are in the server log, on a line tagged with the same trace ID.
        assertThat(serverLog.getOut())
                .contains("trace=" + traceId)
                .contains("hunter2")
                .contains("IllegalStateException");
    }

    // ------------------------------------------------------------------ framework errors keep their status

    @Test
    @WithMockUser
    void aUrlThatDoesNotExistIs404NotA500() throws Exception {
        mvc.perform(get("/api/no-such-thing"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.traceId").exists());
    }

    @Test
    @WithMockUser
    void theWrongHttpMethodIs405AndSaysWhichAreAllowed() throws Exception {
        mvc.perform(post("/api/health"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", containsString("GET")))
                .andExpect(jsonPath("$.error").value("Method Not Allowed"));
    }

    @Test
    @WithMockUser
    void aWronglyTypedUrlValueIs400() throws Exception {
        mvc.perform(get("/api/test/items/not-a-number"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("A value in the request has the wrong type"))
                .andExpect(content().string(not(containsString("not-a-number"))));
    }

    // ------------------------------------------------------------------ trace IDs

    @Test
    void everyResponseGetsItsOwnTraceId() throws Exception {
        String first = mvc.perform(get("/api/health")).andReturn().getResponse().getHeader(TraceIds.HEADER);
        String second = mvc.perform(get("/api/health")).andReturn().getResponse().getHeader(TraceIds.HEADER);

        assertThat(first).isNotBlank().hasSize(16);
        assertThat(second).isNotBlank().isNotEqualTo(first);
    }

    @Test
    void securityRefusalsCarryTheTraceIdToo() throws Exception {
        MockHttpServletResponse response = mvc.perform(get("/api/test/crash"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();

        assertThat(bodyTraceId(response)).isEqualTo(response.getHeader(TraceIds.HEADER));
    }

    @Test
    void aTraceIdSentByTheCallerIsIgnored() throws Exception {
        String traceId = mvc.perform(get("/api/health").header(TraceIds.HEADER, "attacker-chosen-id"))
                .andReturn().getResponse().getHeader(TraceIds.HEADER);

        assertThat(traceId).isNotEqualTo("attacker-chosen-id");
    }

    // ------------------------------------------------------------------ security headers

    private static void assertSecurityHeaders(ResultActions result) throws Exception {
        result
                .andExpect(header().string("Content-Security-Policy", SecurityConfig.CONTENT_SECURITY_POLICY))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Permissions-Policy", SecurityConfig.PERMISSIONS_POLICY))
                .andExpect(header().string("Cross-Origin-Opener-Policy", "same-origin"))
                .andExpect(header().string("Cross-Origin-Resource-Policy", "same-origin"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void successfulResponsesCarryTheSecurityHeaders() throws Exception {
        assertSecurityHeaders(mvc.perform(get("/api/health")).andExpect(status().isOk()));
    }

    @Test
    void refusedResponsesCarryTheSecurityHeadersToo() throws Exception {
        assertSecurityHeaders(mvc.perform(get("/api/test/crash")).andExpect(status().isUnauthorized()));
    }

    @Test
    void hstsIsSentOverHttpsAndNotOverPlainHttp() throws Exception {
        mvc.perform(get("/api/health").secure(true))
                .andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"));
        mvc.perform(get("/api/health"))
                .andExpect(header().doesNotExist("Strict-Transport-Security"));
    }

    @Test
    void theServerDoesNotAnnounceItsSoftware() throws Exception {
        mvc.perform(get("/api/health"))
                .andExpect(header().doesNotExist("Server"))
                .andExpect(header().doesNotExist("X-Powered-By"));
    }

    // ------------------------------------------------------------------ request size limit

    @Test
    void aBodyOverTheLimitIsRefusedBeforeItIsRead() throws Exception {
        String huge = "{\"username\":\"" + "x".repeat(300 * 1024) + "\"}";

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(huge))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.error").value("Request body is too large"))
                .andExpect(jsonPath("$.traceId").exists());
    }

    @Test
    void aChunkedBodyWithNoStatedLengthIsRefused() throws Exception {
        mvc.perform(post("/api/auth/login").header("Transfer-Encoding", "chunked")
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isLengthRequired());
    }

    @Test
    @WithMockUser
    void aBodyUnderTheLimitIsAccepted() throws Exception {
        mvc.perform(post("/api/test/echo").contentType(MediaType.TEXT_PLAIN).content("y".repeat(200 * 1024)))
                .andExpect(status().isOk())
                .andExpect(content().string("received 204800 characters"));
    }
}
