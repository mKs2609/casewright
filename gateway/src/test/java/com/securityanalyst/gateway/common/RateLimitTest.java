package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;

/**
 * Rate limits end to end, with tight limits set just for this class. The counters are
 * shared by all tests here, so each test pretends to come from its own IP addresses.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RateLimitTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";

    @DynamicPropertySource
    static void tightLimits(DynamicPropertyRegistry registry) {
        registry.add("security.rate-limit.requests-per-minute", () -> 20);
        registry.add("security.rate-limit.credential-requests-per-minute", () -> 4);
        registry.add("security.rate-limit.free-login-attempts", () -> 2);
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private ResultActions login(String fromIp, String username, String password) throws Exception {
        return mvc.perform(post("/api/auth/login")
                .with(request -> {
                    request.setRemoteAddr(fromIp);
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"));
    }

    @Test
    void afterTheFreeAttemptsEvenTheRightPasswordMustWaitButWorksAfterwards() throws Exception {
        users.save(new User("asha.rao", passwordEncoder.encode(PASSWORD), Role.VIEWER));

        // Two wrong guesses, from two different addresses: the limit follows the account, not the IP.
        login("10.0.1.1", "asha.rao", "wrong guess number 1").andExpect(status().isUnauthorized());
        login("10.0.1.2", "asha.rao", "wrong guess number 2").andExpect(status().isUnauthorized());

        // The right password, from a third address, is refused without being checked.
        login("10.0.1.3", "asha.rao", PASSWORD)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "1"))
                .andExpect(jsonPath("$.error").value("Too many login attempts. Try again later."))
                .andExpect(jsonPath("$.traceId").exists());

        // No permanent lockout: once the wait is over, the right password works.
        Thread.sleep(1_100);
        login("10.0.1.3", "asha.rao", PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anUnknownUsernameIsThrottledExactlyLikeARealOne() throws Exception {
        users.save(new User("ravi.k", passwordEncoder.encode(PASSWORD), Role.VIEWER));
        for (String username : new String[] { "ravi.k", "nobody.here" }) {
            login("10.0.2.1", username, "wrong guess number 1").andExpect(status().isUnauthorized());
            login("10.0.2.2", username, "wrong guess number 2").andExpect(status().isUnauthorized());
        }

        MvcResult real = login("10.0.2.3", "ravi.k", "wrong guess number 3").andReturn();
        MvcResult unknown = login("10.0.2.4", "nobody.here", "wrong guess number 3").andReturn();

        assertThat(real.getResponse().getStatus()).isEqualTo(429);
        assertThat(unknown.getResponse().getStatus()).isEqualTo(429);
        assertThat(unknown.getResponse().getHeader("Retry-After")).isEqualTo(real.getResponse().getHeader("Retry-After"));
        assertThat(withoutTraceId(unknown.getResponse().getContentAsString()))
                .isEqualTo(withoutTraceId(real.getResponse().getContentAsString()));
    }

    @Test
    void oneAddressCanOnlyTryLoginsSoOftenButOthersAreUnaffected() throws Exception {
        // Different usernames each time, so only the per-address limit (4 a minute) is in play.
        for (int i = 1; i <= 4; i++) {
            login("10.0.3.1", "guess.user" + i, "some wrong password").andExpect(status().isUnauthorized());
        }

        login("10.0.3.1", "guess.user5", "some wrong password")
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.error").value("Too many requests. Try again later."))
                .andExpect(jsonPath("$.traceId").exists())
                // Refusals still carry the protective headers.
                .andExpect(header().string("Content-Security-Policy", SecurityConfig.CONTENT_SECURITY_POLICY));

        login("10.0.3.2", "guess.user5", "some wrong password").andExpect(status().isUnauthorized());
        // The strict limit is only for login and signup; the same address can still use the rest.
        mvc.perform(get("/api/health").with(request -> {
            request.setRemoteAddr("10.0.3.1");
            return request;
        })).andExpect(status().isOk());
    }

    @Test
    void everyAddressHasAGeneralLimitOnAllRequests() throws Exception {
        for (int i = 1; i <= 20; i++) {
            mvc.perform(get("/api/health").with(request -> {
                request.setRemoteAddr("10.0.4.1");
                return request;
            })).andExpect(status().isOk());
        }

        mvc.perform(get("/api/health").with(request -> {
            request.setRemoteAddr("10.0.4.1");
            return request;
        })).andExpect(status().isTooManyRequests()).andExpect(header().exists("Retry-After"));
    }

    @Test
    void aForgedForwardedForHeaderDoesNotGiveAFreshAllowance() throws Exception {
        for (int i = 1; i <= 4; i++) {
            login("10.0.5.1", "forged.user" + i, "some wrong password").andExpect(status().isUnauthorized());
        }

        mvc.perform(post("/api/auth/login")
                .with(request -> {
                    request.setRemoteAddr("10.0.5.1");
                    return request;
                })
                .header("X-Forwarded-For", "203.0.113.77")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"forged.user5\",\"password\":\"some wrong password\"}"))
                .andExpect(status().isTooManyRequests());
    }

    private static String withoutTraceId(String json) {
        return json.replaceAll("\"traceId\":\"[0-9a-f]{16}\"", "\"traceId\":\"*\"");
    }
}
