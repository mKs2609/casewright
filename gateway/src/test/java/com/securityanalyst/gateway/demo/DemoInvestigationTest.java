package com.securityanalyst.gateway.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;
import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;

import jakarta.servlet.http.Cookie;

/**
 * Firing a scenario for real: committed, so its investigation starts. Not @Transactional on
 * purpose (a test transaction would hide a submit that has none of its own). No agent runs in
 * tests, so the investigation ends in error, which still proves it started.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DemoInvestigationTest extends PostgresIntegrationTest {

    private static final String USERNAME = "dora.demo.run";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    @AfterEach
    void deleteWhatThisClassSaved() {
        jdbc.update("DELETE FROM incidents WHERE created_by IN (SELECT id FROM app_users WHERE username = ?)", USERNAME);
        jdbc.update("DELETE FROM app_users WHERE username = ?", USERNAME);
    }

    @Test
    void aFiredScenarioIsSavedAndInvestigated() throws Exception {
        users.save(new User(USERNAME, passwordEncoder.encode("correct horse battery staple"), Role.ANALYST));
        Cookie analyst = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + USERNAME + "\",\"password\":\"correct horse battery staple\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);

        String created = mvc.perform(post("/api/demo/vishing_call").cookie(analyst))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        Integer id = JsonPath.read(created, "$.id");

        Instant giveUp = Instant.now().plusSeconds(10);
        String state;
        do {
            Thread.sleep(50);
            state = jdbc.queryForObject("SELECT status FROM incidents WHERE id = ?", String.class, id);
        } while (!state.equals("error") && Instant.now().isBefore(giveUp));
        assertThat(state).as("the investigation started (and, with no agent running, failed)").isEqualTo("error");
        assertThat(jdbc.queryForObject("SELECT source FROM incidents WHERE id = ?", String.class, id)).isEqualTo("demo");
    }
}
