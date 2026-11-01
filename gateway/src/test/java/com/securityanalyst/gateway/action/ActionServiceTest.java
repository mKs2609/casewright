package com.securityanalyst.gateway.action;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.evidence.EvidenceService;

import jakarta.servlet.http.Cookie;
import tools.jackson.databind.json.JsonMapper;

/**
 * The policy and the decisions. Not @Transactional: "noting the expiry survives the refusal" and
 * "only one of two decisions wins" need real commits. Cleans up its users and incidents; its audit
 * entries stay, as everyone's do.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ActionServiceTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String BAD_IP = "203.0.113.66";
    private static final String BAD_DOMAIN = "paypa1.example";
    private static final String CALLER = "+15555550142";
    private static final String SENDER = "security@paypa1.example";
    private static final String SUBJECT = "priya.sharma";

    @Autowired
    private ActionService actions;
    @Autowired
    private EvidenceService evidence;
    @Autowired
    private AuditLog audit;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private JsonMapper json;
    @Autowired
    private MockMvc mvc;
    @Autowired
    private UserRepository users;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private Long incident;
    private Cookie analyst;

    private Cookie login(String username, Role role) throws Exception {
        users.save(new User(username, passwordEncoder.encode(PASSWORD), role));
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
    }

    @BeforeEach
    void anInvestigatedIncident() throws Exception {
        clean();
        analyst = login("action.analyst", Role.ANALYST);
        Long creator = users.findByUsername("action.analyst").orElseThrow().getId();
        String payload = "{\"kind\":\"email\",\"subjectIdentity\":\"" + SUBJECT + "\",\"sender\":\"" + SENDER
                + "\",\"callerNumber\":\"" + CALLER + "\",\"events\":[{\"username\":\"arjun.mehta\"}]}";
        incident = jdbc.queryForObject("""
                INSERT INTO incidents (kind, subject_identity, payload, status, source, created_by)
                VALUES ('email', ?, ?::jsonb, 'awaiting_approval', 'api', ?) RETURNING id""",
                Long.class, SUBJECT, payload, creator);
        for (String[] indicator : new String[][] { { "ip", BAD_IP }, { "ip", "10.0.0.5" }, { "ip", "198.51.100.9" },
                { "domain", BAD_DOMAIN }, { "domain", "mail.example.com" }, { "domain", "other.example" },
                { "email", SENDER }, { "phone", CALLER } }) {
            jdbc.update("INSERT INTO incident_indicators (incident_id, type, value) VALUES (?, ?, ?)",
                    incident, indicator[0], indicator[1]);
        }
        List<Map<String, Object>> signals = new ArrayList<>();
        for (String target : List.of(BAD_IP, "10.0.0.5", BAD_DOMAIN, "mail.example.com", CALLER)) {
            signals.add(Map.of("id", "REP-MALICIOUS", "label", "known bad", "plain", "known bad", "weight", 45, "indicator", target));
        }
        evidence.recordAccepted(incident, "E1", "reputation_lookup", Map.of(), "summary", json.readTree("{}"), signals);
        evidence.recordAccepted(incident, "E2", "baseline_check", Map.of(), "summary", json.readTree("{}"), List.of());
    }

    @AfterEach
    void clean() {
        jdbc.update("DELETE FROM incidents WHERE created_by IN (SELECT id FROM app_users WHERE username LIKE 'action.%' OR username = ?)", SUBJECT);
        jdbc.update("DELETE FROM app_users WHERE username LIKE 'action.%' OR username = ?", SUBJECT);
    }

    private int apply(String verdict, String action, String target, String evidenceLabel) {
        return actions.apply(incident, List.of(new ActionService.Proposal(action, target, evidenceLabel)), verdict, SUBJECT,
                jdbc.queryForObject("SELECT payload::text FROM incidents WHERE id = ?", String.class, incident));
    }

    private Long pendingBlock() {
        assertThat(apply("malicious", "block_ip", BAD_IP, "E1")).isEqualTo(1);
        return actions.forIncident(incident).getLast().id();
    }

    private ResultActions decide(Long id, String decision, Cookie who) throws Exception {
        return mvc.perform(post("/api/actions/" + id + "/decision").cookie(who).contentType(MediaType.APPLICATION_JSON)
                .content("{\"decision\":\"" + decision + "\"}"));
    }

    private int enforced() {
        return jdbc.queryForObject("SELECT count(*) FROM enforcement e JOIN actions a ON a.id = e.action_id WHERE a.incident_id = ?",
                Integer.class, incident);
    }

    private String incidentStatus() {
        return jdbc.queryForObject("SELECT status FROM incidents WHERE id = ?", String.class, incident);
    }

    private List<String> auditEvents() {
        return jdbc.queryForList("SELECT event FROM audit_log WHERE incident_id = ? ORDER BY seq", String.class, incident);
    }

    // ------------------------------------------------------------------ the policy

    @ParameterizedTest
    @CsvSource({
            "block_ip,203.0.113.66,E1,1",
            "block_sender_domain,paypa1.example,E1,1",
            "block_phone_number,+15555550142,E1,1",
            "quarantine_email,security@paypa1.example,E1,1",
            "force_password_reset,priya.sharma,E1,1",
            "lock_account,arjun.mehta,E1,1",
            "monitor,203.0.113.66,E1,0",
            "notify_user,priya.sharma,E2,0" })
    void anAllowedProposalIsSaved(String action, String target, String evidenceLabel, int waiting) {
        assertThat(apply("malicious", action, target, evidenceLabel)).isEqualTo(waiting);

        assertThat(actions.forIncident(incident)).singleElement().satisfies(saved -> {
            assertThat(saved.status()).isEqualTo(waiting == 1 ? "pending" : "executed");
            assertThat(saved.risk()).isEqualTo(waiting == 1 ? "high" : "low");
        });
        assertThat(enforced()).isEqualTo(waiting == 1 ? 0 : 1);
    }

    @ParameterizedTest
    @CsvSource({
            "block_ip,10.0.0.5,E1,internal addresses can never be blocked",
            "block_ip,192.0.2.200,E1,the address is not in the incident",
            "block_ip,198.51.100.9,E1,the evidence has no finding about this address",
            "block_ip,203.0.113.66,E2,the evidence has no finding about this address",
            "block_ip,203.0.113.66,E9,it cites evidence that does not exist",
            "notify_user,priya.sharma,E9,it cites evidence that does not exist",
            "force_password_reset,priya.sharma,E2,the evidence has no finding",
            "block_sender_domain,mail.example.com,E1,a protected domain can never be blocked",
            "block_sender_domain,attacker.example,E1,the domain is not in the incident",
            "block_sender_domain,other.example,E1,the evidence has no finding about this domain",
            "block_phone_number,+15555550199,E1,the number is not the caller's",
            "quarantine_email,it-support@example.com,E1,the target is not the sender",
            "force_password_reset,ceo.office,E1,the target is not a person in the incident",
            "lock_account,ceo.office,E1,the target is not a person in the incident",
            "notify_user,ceo.office,E2,the target is not a person in the incident",
            "monitor,ceo.office,E2,the target is not part of the incident" })
    void aProposalOutsideThePolicyIsRefusedAndRecorded(String action, String target, String evidenceLabel, String reason) {
        assertThat(apply("malicious", action, target, evidenceLabel)).isZero();

        assertThat(actions.forIncident(incident)).isEmpty();
        assertThat(jdbc.queryForList("SELECT data::text FROM audit_log WHERE incident_id = ? AND event = 'action.refused'",
                String.class, incident)).singleElement().asString().contains(reason).doesNotContain(target);
    }

    @Test
    void aHighRiskActionCannotFollowABenignVerdict() {
        assertThat(apply("benign", "block_ip", BAD_IP, "E1")).isZero();

        assertThat(actions.forIncident(incident)).isEmpty();
    }

    @Test
    void theSameProposalTwiceIsSavedOnce() {
        ActionService.Proposal twice = new ActionService.Proposal("block_ip", BAD_IP, "E1");

        assertThat(actions.apply(incident, List.of(twice, twice), "malicious", SUBJECT, "{}")).isEqualTo(1);
    }

    @ParameterizedTest
    @CsvSource({ "::1,true", "fd00::1,true", "fe80::1,true", "169.254.1.1,true", "172.16.0.1,true", "192.168.1.1,true",
            "127.0.0.1,true", "::ffff:10.0.0.5,true", "203.0.113.66,false", "192.0.2.150,false", "2001:db8::1,false" })
    void internalAddressesAreTheSameOnesTheAgentMeans(String ip, boolean internal) {
        assertThat(ActionPolicy.isInternal(ip)).isEqualTo(internal);
    }

    // ------------------------------------------------------------------ deciding

    @Test
    void approvingRunsTheActionRecordsWhoAndSettlesTheIncident() throws Exception {
        Long id = pendingBlock();

        decide(id, "approve", analyst).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("executed"))
                .andExpect(jsonPath("$.decidedBy").value("action.analyst"));

        assertThat(enforced()).isEqualTo(1);
        assertThat(incidentStatus()).isEqualTo("needs_review");
        assertThat(auditEvents()).contains("action.proposed", "action.approved", "incident.status");
        assertThat(audit.verify().valid()).isTrue();
    }

    @Test
    void rejectingRunsNothing() throws Exception {
        Long id = pendingBlock();

        decide(id, "reject", analyst).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("rejected"));

        assertThat(enforced()).isZero();
        assertThat(incidentStatus()).isEqualTo("needs_review");
        assertThat(auditEvents()).contains("action.rejected");
    }

    @Test
    void theIncidentKeepsWaitingWhileAnythingIsStillPending() throws Exception {
        Long first = pendingBlock();
        apply("malicious", "block_sender_domain", BAD_DOMAIN, "E1");

        decide(first, "approve", analyst).andExpect(status().isOk());

        assertThat(incidentStatus()).isEqualTo("awaiting_approval");
    }

    @Test
    void aViewerCannotDecide() throws Exception {
        Long id = pendingBlock();

        decide(id, "approve", login("action.viewer", Role.VIEWER)).andExpect(status().isForbidden());

        assertThat(enforced()).isZero();
    }

    @Test
    void decidingNeedsALogin() throws Exception {
        mvc.perform(post("/api/actions/1/decision").contentType(MediaType.APPLICATION_JSON).content("{\"decision\":\"approve\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void nobodyDecidesAnActionOnTheirOwnAccount() throws Exception {
        assertThat(apply("malicious", "force_password_reset", SUBJECT, "E1")).isEqualTo(1);
        Long id = actions.forIncident(incident).getLast().id();

        decide(id, "approve", login(SUBJECT, Role.ANALYST)).andExpect(status().isForbidden());
        decide(id, "reject", analyst).andExpect(status().isOk());
    }

    @Test
    void theSubmitterMayDecideOtherTargets() throws Exception {
        // ADR-47: one analyst can run the system; the audit log shows who submitted and who decided.
        decide(pendingBlock(), "approve", analyst).andExpect(status().isOk());
    }

    @Test
    void aDecisionCannotBeChanged() throws Exception {
        Long id = pendingBlock();
        decide(id, "reject", analyst).andExpect(status().isOk());

        decide(id, "approve", analyst).andExpect(status().isConflict());

        assertThat(enforced()).isZero();
    }

    @Test
    void anUnknownDecisionOrActionIsRefused() throws Exception {
        decide(pendingBlock(), "maybe", analyst).andExpect(status().isBadRequest());
        decide(999_999_999L, "approve", analyst).andExpect(status().isNotFound());
    }

    @Test
    void twoDecisionsAtOnceHaveOneWinner() throws Exception {
        Long id = pendingBlock();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<Integer>> both = List.of(
                    pool.submit(() -> decide(id, "approve", analyst).andReturn().getResponse().getStatus()),
                    pool.submit(() -> decide(id, "approve", analyst).andReturn().getResponse().getStatus()));
            assertThat(List.of(both.get(0).get(), both.get(1).get())).containsExactlyInAnyOrder(200, 409);
        } finally {
            pool.shutdown();
        }

        assertThat(enforced()).isEqualTo(1);
    }

    // ------------------------------------------------------------------ expiry

    private void pastItsDeadline(Long id) {
        jdbc.update("UPDATE actions SET expires_at = now() - interval '1 minute' WHERE id = ?", id);
    }

    @Test
    void aPendingActionGetsADeadlineFromTheSetting() {
        Long id = pendingBlock();

        assertThat(jdbc.queryForObject("SELECT expires_at BETWEEN now() + interval '23 hours 59 minutes' AND now() + interval '24 hours' "
                + "FROM actions WHERE id = ?", Boolean.class, id)).isTrue();
    }

    @Test
    void aLateDecisionIsRefusedAndTheExpiryIsStillSaved() throws Exception {
        Long id = pendingBlock();
        pastItsDeadline(id);

        decide(id, "approve", analyst).andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("This action has expired"));

        assertThat(enforced()).isZero();
        assertThat(actions.forIncident(incident).getLast().status()).isEqualTo("expired");
        assertThat(auditEvents()).contains("action.expired");
    }

    @Test
    void aDecidedActionPastItsDeadlineStillSaysDecidedNotExpired() throws Exception {
        Long id = pendingBlock();
        decide(id, "reject", analyst).andExpect(status().isOk());
        pastItsDeadline(id);

        decide(id, "approve", analyst).andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("This action has already been decided"));
    }

    @Test
    void theRegularCheckExpiresWhatIsOverdueAndSettlesTheIncident() {
        Long id = pendingBlock();
        pastItsDeadline(id);

        actions.expireDue();

        assertThat(actions.forIncident(incident).getLast().status()).isEqualTo("expired");
        assertThat(incidentStatus()).isEqualTo("needs_review");
        assertThat(enforced()).isZero();
    }

    @Test
    void theRegularCheckLeavesAnythingStillInTimeAlone() {
        Long id = pendingBlock();

        actions.expireDue();

        assertThat(actions.forIncident(incident).getLast().id()).isEqualTo(id);
        assertThat(actions.forIncident(incident).getLast().status()).isEqualTo("pending");
    }

    // ------------------------------------------------------------------ listing

    @Test
    void anyLoggedInUserCanListWhatIsWaiting() throws Exception {
        Long id = pendingBlock();

        mvc.perform(get("/api/actions").cookie(login("action.viewer", Role.VIEWER)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == " + id + ")].target").value(BAD_IP));
        mvc.perform(get("/api/actions").param("status", "nonsense").cookie(analyst)).andExpect(status().isBadRequest());
        mvc.perform(get("/api/actions")).andExpect(status().isUnauthorized());
    }
}
