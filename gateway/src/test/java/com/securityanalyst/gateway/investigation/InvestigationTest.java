package com.securityanalyst.gateway.investigation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.contains;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;
import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.identity.Baseline;
import com.sun.net.httpserver.HttpServer;

import jakarta.servlet.http.Cookie;
import jakarta.validation.Validator;
import tools.jackson.databind.json.JsonMapper;

/**
 * The gateway's side of the agent connection, against a fake agent: a tiny web server
 * started by this test, which records what it receives and answers however a test says.
 *
 * Not @Transactional: the investigation runs on a background thread after the incident is
 * committed, so the data must really be saved. Everything is deleted after each test.
 */
@SpringBootTest
@AutoConfigureMockMvc
class InvestigationTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";

    // ------------------------------------------------------------------ the fake agent

    record Received(String path, String authorization, String body) {
    }

    private static final List<Received> RECEIVED = new CopyOnWriteArrayList<>();
    private static volatile int answerStatus;
    private static volatile String answerContentType;
    private static volatile String answerBody;
    private static volatile Duration pauseBeforeLastLine;

    private static final HttpServer FAKE_AGENT = startFakeAgent();

    private static HttpServer startFakeAgent() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(Executors.newCachedThreadPool());
            server.createContext("/", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                RECEIVED.add(new Received(exchange.getRequestURI().getPath(),
                        exchange.getRequestHeaders().getFirst("Authorization"), body));
                exchange.getResponseHeaders().add("Content-Type", answerContentType);
                exchange.sendResponseHeaders(answerStatus, 0);
                try (OutputStream out = exchange.getResponseBody()) {
                    String[] lines = answerBody.split("(?<=\n)");
                    for (int i = 0; i < lines.length; i++) {
                        if (i == lines.length - 1 && !pauseBeforeLastLine.isZero()) {
                            out.flush();
                            Thread.sleep(pauseBeforeLastLine.toMillis());
                        }
                        out.write(lines[i].getBytes(StandardCharsets.UTF_8));
                    }
                } catch (IOException | InterruptedException e) {
                    // The gateway hung up (e.g. it gave up waiting): nothing more to send.
                }
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void useTheFakeAgent(DynamicPropertyRegistry registry) {
        registry.add("agent.base-url", () -> "http://127.0.0.1:" + FAKE_AGENT.getAddress().getPort());
        registry.add("agent.investigation-timeout", () -> "3s");
    }

    private static final String THOUGHT = "{\"type\":\"agent.thought\",\"text\":\"Looking at the sender\"}\n";
    private static String verdict(String verdict, String attackType, int risk, String cited) {
        return "{\"type\":\"verdict\",\"verdict\":\"" + verdict + "\",\"attackType\":\"" + attackType + "\",\"riskScore\":"
                + risk + ",\"citedEvidence\":[" + cited + "],\"counterfactual\":\"Nothing else was checked.\"}\n";
    }

    private static final String COMPLETE_ONLY = "{\"type\":\"investigation.complete\",\"result\":\"needs_review\",\"engine\":\"rules\"}\n";

    /** The usual ending: a cautious verdict (allowed: an agent may be more careful than its evidence), then complete. */
    private static final String COMPLETE = verdict("suspicious", "other", 0, "") + COMPLETE_ONLY;

    private static String step(String label, String value, String signals) {
        return "{\"type\":\"agent.step\",\"label\":\"" + label + "\",\"tool\":\"reputation_lookup\","
                + "\"args\":{\"indicatorType\":\"domain\",\"value\":\"" + value + "\"},"
                + "\"summary\":\"domain " + value + ": score=96\",\"result\":{\"score\":96},"
                + "\"signals\":[" + signals + "]}\n";
    }

    private static final String LOOKALIKE = "{\"id\":\"LOOKALIKE-DOMAIN\",\"label\":\"paypa1.example imitates paypal.com\","
            + "\"plain\":\"The address is made to look like paypal.com, but it isn't.\",\"weight\":35,"
            + "\"mitre\":\"T1583.001\",\"indicator\":\"paypa1.example\"}";

    private static final String REFUSED = "{\"type\":\"agent.guardrail\",\"label\":\"R1\",\"tool\":\"reputation_lookup\","
            + "\"args\":{\"indicatorType\":\"domain\",\"value\":\"attacker-server.example\"},"
            + "\"reason\":\"This domain does not appear in the incident\"}\n";

    private static void agentAnswers(String body) {
        answerStatus = 200;
        answerContentType = "application/x-ndjson";
        answerBody = body;
    }

    // ------------------------------------------------------------------ setup

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AgentClient agentClient;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private JsonMapper json;

    @Autowired
    private Validator validator;

    @BeforeEach
    void reset() {
        RECEIVED.clear();
        pauseBeforeLastLine = Duration.ZERO;
        agentAnswers(THOUGHT + COMPLETE);
    }

    @AfterEach
    void deleteEverythingThisTestSaved() {
        jdbc.update("DELETE FROM incidents");
        jdbc.update("DELETE FROM app_users WHERE username = 'ivy.analyst'");
    }

    private AgentRequest someRequest() {
        Baseline baseline = new Baseline(List.of("IN"), 3, 15, List.of(), List.of(), List.of(), "Bengaluru");
        return new AgentRequest(new AgentRequest.IncidentPart(1L, "email", "priya.sharma", json.readTree("{}")), baseline,
                List.of());
    }

    private Cookie analyst;

    private Integer submitAnEmailIncident() throws Exception {
        users.save(new User("ivy.analyst", passwordEncoder.encode(PASSWORD), Role.ANALYST));
        analyst = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"ivy.analyst\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
        String created = mvc.perform(post("/api/incidents").cookie(analyst).contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"kind": "email", "subjectIdentity": "priya.sharma", "sender": "security@paypa1.example",
                         "subject": "Account locked", "body": "Verify your password"}
                        """))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(created, "$.id");
    }

    /** The investigation runs in the background; wait (up to 10 s) for it to settle. */
    private String finalStatusOf(Integer incidentId) throws InterruptedException {
        Instant giveUp = Instant.now().plusSeconds(10);
        String status;
        do {
            Thread.sleep(50);
            status = jdbc.queryForObject("SELECT status FROM incidents WHERE id = ?", String.class, incidentId);
        } while ((status.equals("queued") || status.equals("investigating")) && Instant.now().isBefore(giveUp));
        return status;
    }

    // ------------------------------------------------------------------ end to end

    @Test
    void aSubmittedIncidentIsSentToTheAgentWithTheTokenAndEndsWithTheAgentsResult() throws Exception {
        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");

        assertThat(RECEIVED).hasSize(1);
        Received call = RECEIVED.getFirst();
        assertThat(call.path()).isEqualTo("/internal/investigate");
        assertThat(call.authorization()).isEqualTo("Bearer " + TEST_AGENT_TOKEN);
        // ADR-3: everything the agent needs travels with the request, the baseline decrypted.
        assertThat((Integer) JsonPath.read(call.body(), "$.incident.id")).isEqualTo(id);
        assertThat((String) JsonPath.read(call.body(), "$.incident.kind")).isEqualTo("email");
        assertThat((String) JsonPath.read(call.body(), "$.incident.payload.sender")).isEqualTo("security@paypa1.example");
        assertThat((String) JsonPath.read(call.body(), "$.baseline.homeCity")).isEqualTo("Bengaluru");
        assertThat((List<String>) JsonPath.read(call.body(), "$.baseline.usualCountries")).containsExactly("IN");
    }

    @Test
    void ifTheAgentRefusesTheIncidentEndsInError() throws Exception {
        answerStatus = 401;

        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void ifTheAgentIsNotRunningTheIncidentEndsInError() {
        AgentProperties nowhere = new AgentProperties(URI.create("http://127.0.0.1:1"), TEST_AGENT_TOKEN,
                Duration.ofSeconds(2), Duration.ofSeconds(3));
        AgentClient client = new AgentClient(nowhere, json, validator);

        assertThatThrownBy(() -> client.investigate(someRequest(), event -> { }))
                .isInstanceOf(AgentException.class)
                .hasMessageContaining("Could not reach the agent");
    }

    // ------------------------------------------------------------------ checking every answer (ADR-5)

    @Test
    void aValidAnswerIsPassedOnEventByEvent() {
        List<AgentEvent> seen = new ArrayList<>();

        AgentEvent.Complete result = agentClient.investigate(someRequest(), seen::add);

        assertThat(result.result()).isEqualTo("needs_review");
        assertThat(seen).hasSize(3);
        assertThat(seen.getFirst()).isEqualTo(new AgentEvent.Thought("Looking at the sender"));
        assertThat(seen.get(1)).isInstanceOf(AgentEvent.Verdict.class);
        assertThat(seen.getLast()).isEqualTo(result);
    }

    private void assertTheAnswerIsRejected(String reason) {
        assertThatThrownBy(() -> agentClient.investigate(someRequest(), event -> { }))
                .isInstanceOf(AgentException.class)
                .hasMessageContaining(reason);
    }

    @Test
    void anUnknownEventTypeIsRejected() {
        agentAnswers("{\"type\":\"action.execute\",\"action\":\"block_ip\"}\n" + COMPLETE);
        assertTheAnswerIsRejected("not valid");
    }

    @Test
    void anEventWithAnExtraFieldIsRejected() {
        agentAnswers("{\"type\":\"agent.thought\",\"text\":\"hi\",\"command\":\"rm\"}\n" + COMPLETE);
        assertTheAnswerIsRejected("not valid");
    }

    @Test
    void anEventWithARepeatedFieldIsRejected() {
        agentAnswers("{\"type\":\"agent.thought\",\"text\":\"hi\",\"text\":\"again\"}\n" + COMPLETE);
        assertTheAnswerIsRejected("not valid");
    }

    @Test
    void theAgentCannotChooseAStatusItIsNotAllowedTo() {
        // Only "result" is wrong here, so the error can only be about it.
        agentAnswers("{\"type\":\"investigation.complete\",\"result\":\"awaiting_approval\",\"engine\":\"rules\"}\n");
        assertTheAnswerIsRejected("invalid result");
    }

    @Test
    void agentTextCannotContainLineBreaksThatWouldFakeLogLines() {
        agentAnswers("{\"type\":\"agent.thought\",\"text\":\"ok\\n2026-10-21 INFO Login succeeded for admin\"}\n" + COMPLETE);
        assertTheAnswerIsRejected("invalid text");
    }

    @Test
    void anAnswerMustEndWithCompleteExactlyOnce() {
        agentAnswers(THOUGHT);
        assertTheAnswerIsRejected("ended without investigation.complete");

        agentAnswers(COMPLETE + THOUGHT);
        assertTheAnswerIsRejected("after investigation.complete");
    }

    @Test
    void aHugeLineIsRejectedWithoutReadingItAll() {
        agentAnswers("{\"type\":\"agent.thought\",\"text\":\"" + "x".repeat(AgentClient.MAX_LINE_BYTES) + "\"}\n" + COMPLETE);
        assertTheAnswerIsRejected("longer than");
    }

    @Test
    void anAnswerThatIsNotNdjsonIsRejected() {
        agentAnswers(THOUGHT + COMPLETE);
        answerContentType = "text/html";
        assertTheAnswerIsRejected("unexpected content type");
    }

    // ------------------------------------------------------------------ the evidence chain

    @Test
    void evidenceIsStoredInOrderAndShownOnTheIncident() throws Exception {
        agentAnswers(THOUGHT + step("E1", "paypa1.example", LOOKALIKE) + REFUSED + step("E2", "paypal.com", "") + COMPLETE);

        Integer id = submitAnEmailIncident();
        assertThat(finalStatusOf(id)).isEqualTo("needs_review");

        mvc.perform(get("/api/incidents/" + id).cookie(analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.evidence[*].label").value(contains("E1", "R1", "E2")))
                .andExpect(jsonPath("$.evidence[0].status").value("ok"))
                .andExpect(jsonPath("$.evidence[0].args.value").value("paypa1.example"))
                .andExpect(jsonPath("$.evidence[0].signals[0].id").value("LOOKALIKE-DOMAIN"))
                .andExpect(jsonPath("$.evidence[0].signals[0].plain").value("The address is made to look like paypal.com, but it isn't."))
                .andExpect(jsonPath("$.evidence[1].status").value("rejected"))
                .andExpect(jsonPath("$.evidence[1].reason").value("This domain does not appear in the incident"))
                .andExpect(jsonPath("$.evidence[1].result").doesNotExist())
                .andExpect(jsonPath("$.evidence[2].signals").isEmpty());
    }

    @Test
    void evidenceOutOfOrderEndsInErrorButWhatCameBeforeIsKept() throws Exception {
        // E1 is fine; then a repeated E1 (as if rewriting it) must stop the investigation.
        agentAnswers(step("E1", "paypa1.example", "") + step("E1", "paypal.com", "") + COMPLETE);

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("error");
        assertThat(jdbc.queryForList("SELECT label FROM evidence WHERE incident_id = ?", String.class, id))
                .containsExactly("E1");
    }

    @Test
    void evidenceThatSkipsANumberEndsInError() throws Exception {
        agentAnswers(step("E2", "paypa1.example", "") + COMPLETE);

        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void aStepMustNameAKnownToolAndSaneSignals() {
        agentAnswers(step("E1", "paypa1.example", "").replace("reputation_lookup", "delete_mailbox") + COMPLETE);
        assertTheAnswerIsRejected("invalid tool");

        agentAnswers(step("E1", "paypa1.example", LOOKALIKE.replace("\"weight\":35", "\"weight\":150")) + COMPLETE);
        assertTheAnswerIsRejected("weight");
    }

    @Test
    void allFourToolsAreAcceptedAndNothingElse() {
        for (String tool : new String[] { "reputation_lookup", "baseline_check", "pattern_match", "correlate_events" }) {
            agentAnswers(step("E1", "paypa1.example", "").replace("reputation_lookup", tool) + COMPLETE);
            assertThat(agentClient.investigate(someRequest(), event -> { }).result()).isEqualTo("needs_review");
        }
        agentAnswers(step("E1", "paypa1.example", "").replace("reputation_lookup", "send_email") + COMPLETE);
        assertTheAnswerIsRejected("invalid tool");
    }

    @Test
    void aStepWithoutAResultObjectEndsInError() throws Exception {
        agentAnswers(step("E1", "paypa1.example", "").replace("\"result\":{\"score\":96}", "\"result\":\"fine\"") + COMPLETE);

        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void theDatabaseItselfRefusesARefusedCallWithAResult() throws Exception {
        Integer id = submitAnEmailIncident();
        finalStatusOf(id);

        assertThatThrownBy(() -> jdbc.update("INSERT INTO evidence (incident_id, label, tool, args, status, reason, result) "
                + "VALUES (?, 'R9', 'reputation_lookup', '{}', 'rejected', 'no', '{}')", id))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // ------------------------------------------------------------------ related incidents (step 10b)

    private static String indicators(String json) {
        return "{\"type\":\"incident.indicators\",\"indicators\":[" + json + "]}\n";
    }

    private static final String PHISHING_DOMAIN = "{\"type\":\"domain\",\"value\":\"paypa1-secure-login.example\"}";

    @Test
    void theReportedIndicatorsAreStoredWithTheIncident() throws Exception {
        agentAnswers(indicators(PHISHING_DOMAIN + ",{\"type\":\"ip\",\"value\":\"203.0.113.66\"}") + COMPLETE);

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        assertThat(jdbc.queryForList("SELECT type || ':' || value FROM incident_indicators WHERE incident_id = ? ORDER BY 1",
                String.class, id)).containsExactly("domain:paypa1-secure-login.example", "ip:203.0.113.66");
    }

    @Test
    void anIndicatorThatDoesNotLookLikeItsTypeIsRejected() {
        for (String bad : new String[] {
                "{\"type\":\"ip\",\"value\":\"rm -rf /\"}",
                "{\"type\":\"ip\",\"value\":\"185.220.101\"}",
                "{\"type\":\"domain\",\"value\":\"not a domain\"}",
                "{\"type\":\"phone\",\"value\":\"call me\"}",
                "{\"type\":\"url\",\"value\":\"https://x.example\"}" }) {
            agentAnswers(indicators(bad) + COMPLETE);
            assertTheAnswerIsRejected("invalid");
        }
    }

    @Test
    void indicatorsReportedTwiceEndInError() throws Exception {
        agentAnswers(indicators(PHISHING_DOMAIN) + indicators(PHISHING_DOMAIN) + COMPLETE);

        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void theNextIncidentIsToldWhichRecentIncidentsSharedIndicators() throws Exception {
        agentAnswers(indicators(PHISHING_DOMAIN) + COMPLETE);
        Integer first = submitAnEmailIncident();
        finalStatusOf(first);
        RECEIVED.clear();

        Integer second = submitAnotherEmailIncident();
        finalStatusOf(second);

        String sent = RECEIVED.getFirst().body();
        assertThat((List<String>) JsonPath.read(sent, "$.recentIndicators[*].value"))
                .containsExactly("paypa1-secure-login.example");
        assertThat((List<Integer>) JsonPath.read(sent, "$.recentIndicators[0].incidentIds")).containsExactly(first);
        // Values and incident numbers only: nothing about who the earlier incident was about.
        assertThat(sent.substring(sent.indexOf("recentIndicators"))).doesNotContain("priya.sharma");
    }

    @Test
    void incidentsOlderThanTheWindowAreNotSent() throws Exception {
        agentAnswers(indicators(PHISHING_DOMAIN) + COMPLETE);
        Integer first = submitAnEmailIncident();
        finalStatusOf(first);
        jdbc.update("UPDATE incidents SET created_at = now() - interval '8 days' WHERE id = ?", first);
        RECEIVED.clear();

        finalStatusOf(submitAnotherEmailIncident());

        assertThat((List<?>) JsonPath.read(RECEIVED.getFirst().body(), "$.recentIndicators")).isEmpty();
    }

    /** A second incident by the same analyst (the account already exists). */
    private Integer submitAnotherEmailIncident() throws Exception {
        String created = mvc.perform(post("/api/incidents").cookie(analyst).contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"kind": "email", "subjectIdentity": "arjun.mehta", "sender": "help@paypa1-secure-login.example",
                         "subject": "Hello", "body": "Hello again"}
                        """))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(created, "$.id");
    }

    // ------------------------------------------------------------------ the verdict and the score floor (step 11)

    private static final String KNOWN_BAD = "{\"id\":\"REP-MALICIOUS\",\"label\":\"paypa1.example is known-malicious\","
            + "\"plain\":\"This website is on lists of known attackers.\",\"weight\":45}";
    private static final String NEW_DOMAIN = "{\"id\":\"NEW-DOMAIN\",\"label\":\"paypa1.example was registered 3 days ago\","
            + "\"plain\":\"The website was created only days ago.\",\"weight\":15}";

    /** 45, 35 and 15 combine to 1 - (0.55 x 0.65 x 0.85) = 0.696: risk 70, malicious. */
    private static final String MALICIOUS_EVIDENCE = step("E1", "paypa1.example", KNOWN_BAD + "," + LOOKALIKE + "," + NEW_DOMAIN);

    private Map<String, Object> verdictOf(Integer id) throws Exception {
        String detail = mvc.perform(get("/api/incidents/" + id).cookie(analyst)).andReturn().getResponse().getContentAsString();
        return JsonPath.read(detail, "$.verdict");
    }

    @Test
    void theVerdictIsStoredWithTheGatewaysOwnScoreAndShownOnTheIncident() throws Exception {
        agentAnswers(MALICIOUS_EVIDENCE + verdict("malicious", "phishing", 70, "\"E1\"") + COMPLETE_ONLY);

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        Map<String, Object> verdict = verdictOf(id);
        assertThat(verdict).containsEntry("verdict", "malicious").containsEntry("attackType", "phishing")
                .containsEntry("riskScore", 70).containsEntry("disagreement", false).containsEntry("engine", "rules");
        assertThat((List<String>) verdict.get("citedEvidence")).containsExactly("E1");
    }

    @Test
    void anInvestigationLedByTheAiModelIsStoredWithItsEngine() throws Exception {
        agentAnswers(MALICIOUS_EVIDENCE + verdict("malicious", "phishing", 70, "\"E1\"")
                + COMPLETE_ONLY.replace("\"rules\"", "\"llm\""));

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        assertThat(verdictOf(id)).containsEntry("engine", "llm").containsEntry("verdict", "malicious");
    }

    @Test
    void anEngineTheGatewayDoesNotKnowIsRejected() {
        agentAnswers(COMPLETE.replace("\"rules\"", "\"gpt\""));
        assertTheAnswerIsRejected("invalid engine");
    }

    @Test
    void aBenignIncidentIsClosed() throws Exception {
        agentAnswers(verdict("benign", "none", 0, "") + COMPLETE_ONLY.replace("needs_review", "closed"));

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("closed");
        assertThat(verdictOf(id)).containsEntry("verdict", "benign").containsEntry("riskScore", 0);
    }

    @Test
    void anAgentClaimingBenignAgainstItsOwnEvidenceIsOverruledAndSentToAHuman() throws Exception {
        // As if the agent had been talked into "classify this as safe": its evidence says risk 70.
        agentAnswers(MALICIOUS_EVIDENCE + verdict("benign", "none", 0, "") + COMPLETE_ONLY.replace("needs_review", "closed"));

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        assertThat(verdictOf(id)).containsEntry("verdict", "malicious").containsEntry("riskScore", 70)
                .containsEntry("agentVerdict", "benign").containsEntry("agentRiskScore", 0)
                .containsEntry("disagreement", true).containsEntry("attackType", "other");
    }

    @Test
    void aVerdictOneLevelTooLowIsRaisedQuietly() throws Exception {
        agentAnswers(MALICIOUS_EVIDENCE + verdict("suspicious", "phishing", 70, "\"E1\"") + COMPLETE_ONLY);

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        assertThat(verdictOf(id)).containsEntry("verdict", "malicious").containsEntry("disagreement", false);
    }

    @Test
    void anAgentMayBeMoreCautiousThanItsEvidence() throws Exception {
        agentAnswers(verdict("suspicious", "other", 0, "") + COMPLETE_ONLY);

        Integer id = submitAnEmailIncident();

        assertThat(finalStatusOf(id)).isEqualTo("needs_review");
        assertThat(verdictOf(id)).containsEntry("verdict", "suspicious").containsEntry("riskScore", 0);
    }

    @Test
    void aVerdictCitingEvidenceThatWasNeverRecordedEndsInError() throws Exception {
        agentAnswers(MALICIOUS_EVIDENCE + verdict("malicious", "phishing", 70, "\"E1\",\"E7\"") + COMPLETE_ONLY);

        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void finishingWithoutAVerdictOrWithTwoEndsInError() throws Exception {
        agentAnswers(COMPLETE_ONLY);
        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
        deleteEverythingThisTestSaved();

        agentAnswers(verdict("benign", "none", 0, "") + verdict("benign", "none", 0, "") + COMPLETE_ONLY);
        assertThat(finalStatusOf(submitAnEmailIncident())).isEqualTo("error");
    }

    @Test
    void anAgentThatGoesSilentIsCutOffAtTheDeadline() {
        pauseBeforeLastLine = Duration.ofSeconds(20);
        Instant start = Instant.now();

        assertTheAnswerIsRejected("took too long");
        assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(10));
    }
}
