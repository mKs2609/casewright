package com.securityanalyst.gateway.health;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.securityanalyst.gateway.auth.JwtService;
import com.securityanalyst.gateway.common.SecurityConfig;

/**
 * @WebMvcTest starts only the web layer (no real server, no database),
 * and MockMvc sends fake HTTP requests to it. The database is replaced by a
 * mock so we can decide whether it "works" in each test.
 * The real security rules are imported, so these tests also prove that the
 * health endpoint is reachable without logging in.
 */
@WebMvcTest(HealthController.class)
@Import(SecurityConfig.class)
class HealthControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private JdbcTemplate jdbc;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void healthReturnsUpWhenDatabaseAnswers() throws Exception {
        when(jdbc.queryForObject("SELECT 1", Integer.class)).thenReturn(1);

        mvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("gateway"))
                .andExpect(jsonPath("$.database").value("UP"))
                .andExpect(jsonPath("$.startedAt").exists());
    }

    @Test
    void healthReturns503WithoutLeakingDetailsWhenDatabaseIsDown() throws Exception {
        when(jdbc.queryForObject("SELECT 1", Integer.class))
                .thenThrow(new DataAccessResourceFailureException("password authentication failed for user secret_user"));

        mvc.perform(get("/api/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DOWN"))
                .andExpect(jsonPath("$.database").value("DOWN"))
                .andExpect(content().string(not(containsString("secret_user"))));
    }

    @Test
    void unknownPathAsksForLoginSoStrangersCannotMapTheApi() throws Exception {
        mvc.perform(get("/api/does-not-exist"))
                .andExpect(status().isUnauthorized());
    }
}
