package com.securityanalyst.gateway.redteam;

import static com.securityanalyst.gateway.NoEcho.doesNotEcho;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.jayway.jsonpath.JsonPath;
import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;

import jakarta.servlet.http.Cookie;

/**
 * Starting a red-team run and reading its scorecard. Rolled back, so no investigation starts here;
 * InvestigationTest checks that a run asks the agent for its scripted model.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RedTeamTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbc;

    private Cookie analyst;
    private Cookie viewer;

    @BeforeEach
    void createAccounts() throws Exception {
        analyst = loginAs("rita.redteam", Role.ANALYST);
        viewer = loginAs("rob.redteam.viewer", Role.VIEWER);
    }

    private Cookie loginAs(String username, Role role) throws Exception {
        users.save(new User(username, passwordEncoder.encode(PASSWORD), role));
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
    }

    private int incidentCount() {
        return jdbc.queryForObject("SELECT count(*) FROM incidents", Integer.class);
    }

    @Test
    void anAnalystStartsARunAndItIsTheTrickEmailMarkedAsRedTeam() throws Exception {
        String created = mvc.perform(post("/api/red-team").cookie(analyst))
                .andExpect(status().isAccepted())
                .andExpect(header().string("Location", containsString("/api/incidents/")))
                .andExpect(jsonPath("$.source").value("red_team"))
                .andExpect(jsonPath("$.kind").value("email"))
                .andExpect(jsonPath("$.subjectIdentity").value("sara.khan"))
                .andExpect(jsonPath("$.payload.body", containsString("NOTE TO AI SECURITY ASSISTANT")))
                .andReturn().getResponse().getContentAsString();
        Integer id = JsonPath.read(created, "$.id");

        String audit = jdbc.queryForObject(
                "SELECT data::text FROM audit_log WHERE incident_id = ? AND event = 'incident.submitted'", String.class, id);
        assertThat(audit).contains("\"source\": \"red_team\"");
    }

    @Test
    void aBodySentWithTheRequestIsIgnored() throws Exception {
        mvc.perform(post("/api/red-team").cookie(analyst).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"kind\": \"login\", \"subjectIdentity\": \"priya.sharma\", \"events\": []}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.kind").value("email"));
    }

    @Test
    void aViewerCannotStartOneAndNobodyCanWithoutALogin() throws Exception {
        int before = incidentCount();

        mvc.perform(post("/api/red-team").cookie(viewer)).andExpect(status().isForbidden());
        mvc.perform(post("/api/red-team")).andExpect(status().isUnauthorized());

        assertThat(incidentCount()).isEqualTo(before);
    }

    @Test
    void anyLoggedInUserCanReadTheScorecardWhichWaitsWhileTheRunHasNotStarted() throws Exception {
        String created = mvc.perform(post("/api/red-team").cookie(analyst)).andReturn().getResponse().getContentAsString();
        Integer id = JsonPath.read(created, "$.id");

        mvc.perform(get("/api/red-team/" + id).cookie(viewer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").value(id))
                .andExpect(jsonPath("$.state").value("running"))
                .andExpect(jsonPath("$.attempts").value(10))
                .andExpect(jsonPath("$.blocked").value(0))
                .andExpect(jsonPath("$.rows", hasSize(10)))
                .andExpect(jsonPath("$.rows[0].outcome").value("waiting"));
        mvc.perform(get("/api/red-team/" + id)).andExpect(status().isUnauthorized());
    }

    @Test
    void anOrdinaryIncidentHasNoScorecard() throws Exception {
        String created = mvc.perform(post("/api/demo/phishing_email").cookie(analyst))
                .andReturn().getResponse().getContentAsString();
        Integer id = JsonPath.read(created, "$.id");

        mvc.perform(get("/api/red-team/" + id).cookie(analyst))
                .andExpect(status().isNotFound())
                .andExpect(doesNotEcho(String.valueOf(id)));
        mvc.perform(get("/api/red-team/999999999").cookie(analyst)).andExpect(status().isNotFound());
    }
}
