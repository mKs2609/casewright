package com.securityanalyst.gateway.demo;

import static com.securityanalyst.gateway.NoEcho.doesNotEcho;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.io.ByteArrayResource;
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
import jakarta.validation.Validator;
import tools.jackson.databind.json.JsonMapper;

/**
 * The demo buttons: who may list and fire them, and that what is submitted is the gateway's own
 * copy, through the ordinary path, marked as a demo. Each test is rolled back, so no
 * investigation starts (it waits for a commit).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class DemoScenariosTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private DemoScenarios scenarios;

    @Autowired
    private JsonMapper json;

    @Autowired
    private Validator validator;

    private Cookie analyst;
    private Cookie viewer;

    @BeforeEach
    void createAccounts() throws Exception {
        analyst = loginAs("dina.demo", Role.ANALYST);
        viewer = loginAs("dev.demo.viewer", Role.VIEWER);
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

    // ------------------------------------------------------------------ listing

    @Test
    void anyLoggedInUserSeesTheButtonsWithAttemptBreachFirstAndNoIncidentContent() throws Exception {
        String body = mvc.perform(get("/api/demo/scenarios").cookie(viewer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(6)))
                .andExpect(jsonPath("$[0].name").value("credential_stuffing"))
                .andExpect(jsonPath("$[0].title").value("Attempt breach"))
                .andReturn().getResponse().getContentAsString();

        List<java.util.Map<String, Object>> listed = JsonPath.read(body, "$");
        assertThat(listed).allSatisfy(button -> assertThat(button).containsOnlyKeys("name", "title", "description"));
        assertThat(body).doesNotContain("paypa1", "events", "transcript");
    }

    @Test
    void listingNeedsALogin() throws Exception {
        mvc.perform(get("/api/demo/scenarios")).andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ firing one

    @Test
    void anAnalystFiresAScenarioAndItIsSubmittedLikeAnyIncidentButMarkedAsADemo() throws Exception {
        String created = mvc.perform(post("/api/demo/credential_stuffing").cookie(analyst))
                .andExpect(status().isAccepted())
                .andExpect(header().string("Location", containsString("/api/incidents/")))
                .andExpect(jsonPath("$.source").value("demo"))
                .andExpect(jsonPath("$.status").value("queued"))
                .andExpect(jsonPath("$.kind").value("login"))
                .andExpect(jsonPath("$.subjectIdentity").value("arjun.mehta"))
                .andExpect(jsonPath("$.createdBy").value("dina.demo"))
                .andExpect(jsonPath("$.payload.events", hasSize(44)))
                .andReturn().getResponse().getContentAsString();
        Integer id = JsonPath.read(created, "$.id");

        assertThat(jdbc.queryForObject("SELECT source FROM incidents WHERE id = ?", String.class, id)).isEqualTo("demo");
        String audit = jdbc.queryForObject(
                "SELECT data::text FROM audit_log WHERE incident_id = ? AND event = 'incident.submitted'", String.class, id);
        assertThat(audit).contains("\"source\": \"demo\"", "\"kind\": \"login\"");
    }

    @Test
    void everyScenarioIsAValidIncidentAboutADemoEmployee() throws Exception {
        for (DemoScenarios.Scenario scenario : scenarios.list()) {
            mvc.perform(post("/api/demo/" + scenario.name()).cookie(analyst))
                    .andExpect(status().isAccepted())
                    .andExpect(jsonPath("$.source").value("demo"));
        }
    }

    @Test
    void aBodySentWithTheRequestIsIgnored() throws Exception {
        // Only the name chooses what is submitted: the browser cannot slip its own incident in.
        mvc.perform(post("/api/demo/normal_login").cookie(analyst).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"kind": "email", "subjectIdentity": "sara.khan", "sender": "boss@evil.example",
                                 "subject": "Planted", "body": "Planted by the browser"}
                                """))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.kind").value("login"))
                .andExpect(jsonPath("$.subjectIdentity").value("priya.sharma"));
    }

    @Test
    void aViewerCannotFireOne() throws Exception {
        int before = incidentCount();

        mvc.perform(post("/api/demo/credential_stuffing").cookie(viewer)).andExpect(status().isForbidden());

        assertThat(incidentCount()).isEqualTo(before);
    }

    @Test
    void firingOneNeedsALogin() throws Exception {
        mvc.perform(post("/api/demo/credential_stuffing")).andExpect(status().isUnauthorized());
    }

    @Test
    void anUnknownScenarioIsNotFoundAndItsNameIsNotRepeated() throws Exception {
        int before = incidentCount();

        mvc.perform(post("/api/demo/no_such_scenario_xq").cookie(analyst))
                .andExpect(status().isNotFound())
                .andExpect(doesNotEcho("no_such_scenario_xq"));

        assertThat(incidentCount()).isEqualTo(before);
    }

    // ------------------------------------------------------------------ the file itself

    private DemoScenarios load(String file) {
        return new DemoScenarios(json, validator, new ByteArrayResource(file.getBytes(StandardCharsets.UTF_8)));
    }

    private static String fileWith(String name, String incident) {
        return """
                {"scenarios": [{"name": "%s", "title": "A test", "description": "For a test.", "incident": %s}]}
                """.formatted(name, incident);
    }

    private static final String VALID_LOGIN = """
            {"kind": "login", "subjectIdentity": "priya.sharma", "events": [{"username": "priya.sharma",
             "ip": "198.51.100.7", "timestamp": "2026-10-19T06:10:00Z", "success": true, "country": "IN"}]}""";

    @Test
    void aValidFileLoads() {
        assertThat(load(fileWith("a_test", VALID_LOGIN)).list()).extracting(DemoScenarios.Scenario::name)
                .containsExactly("a_test");
    }

    @Test
    void aScenarioThatBreaksTheIncidentRulesStopsStartupAndSaysWhere() {
        String badAddress = VALID_LOGIN.replace("198.51.100.7", "not-an-address");

        assertThatThrownBy(() -> load(fileWith("bad_one", badAddress)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("bad_one")
                .hasMessageContaining("events[0].ip");
    }

    @Test
    void aScenarioWithAFieldTheApiWouldRefuseStopsStartup() {
        String extraField = VALID_LOGIN.replace("\"kind\": \"login\",", "\"kind\": \"login\", \"role\": \"ADMIN\",");

        assertThatThrownBy(() -> load(fileWith("extra_field", extraField))).isInstanceOf(RuntimeException.class);
    }

    @Test
    void namesMustBeSimpleAndUnique() {
        assertThatThrownBy(() -> load(fileWith("Bad Name", VALID_LOGIN))).isInstanceOf(IllegalStateException.class);
        String twice = """
                {"scenarios": [{"name": "same", "title": "A", "description": "A.", "incident": %s},
                               {"name": "same", "title": "B", "description": "B.", "incident": %s}]}
                """.formatted(VALID_LOGIN, VALID_LOGIN);
        assertThatThrownBy(() -> load(twice)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> load("{\"scenarios\": []}")).isInstanceOf(IllegalStateException.class);
    }
}
