package com.securityanalyst.gateway.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;

import jakarta.servlet.http.Cookie;

/**
 * What gets recorded, committed for real. Not @Transactional on purpose: "the entry survives a
 * refused login" only means something if nothing is rolled back around it. Audit entries stay
 * (they cannot be deleted), so these tests look only at the entries they added.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class AuditEventsTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String USER = "audit.events";

    @Autowired
    private AuditLog audit;
    @Autowired
    private MockMvc mvc;
    @Autowired
    private UserRepository users;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private TransactionTemplate transactions;

    private long before;

    @BeforeEach
    void remember() {
        removeUsers();
        before = lastSeq();
    }

    @AfterEach
    void removeUsers() {
        jdbc.update("DELETE FROM app_users WHERE username LIKE 'audit.%'");   // their refresh tokens go with them
    }

    private long lastSeq() {
        return jdbc.queryForObject("SELECT COALESCE(MAX(seq), 0) FROM audit_log", Long.class);
    }

    /** Entries added since the test began, oldest first. */
    private List<AuditLog.Entry> added() {
        List<AuditLog.Entry> all = new java.util.ArrayList<>(audit.recent(500).stream().filter(e -> e.seq() > before).toList());
        java.util.Collections.reverse(all);
        return all;
    }

    private MockHttpServletResponse login(String username, String password) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}")).andReturn().getResponse();
    }

    private void createUser(String username, Role role) {
        users.save(new User(username, passwordEncoder.encode(PASSWORD), role));
    }

    @Test
    void aFailedLoginOnARealAccountNamesItAndSurvivesTheRefusal() throws Exception {
        createUser(USER, Role.VIEWER);

        assertThat(login(USER, "the wrong password").getStatus()).isEqualTo(401);

        assertThat(added()).singleElement().satisfies(entry -> {
            assertThat(entry.event()).isEqualTo("auth.login_failed");
            assertThat(entry.actor()).isEqualTo(USER);
        });
        assertThat(audit.verify().valid()).isTrue();
    }

    @Test
    void aFailedLoginOnAnUnknownNameNeverRecordsWhatWasTyped() throws Exception {
        // Someone typing their password into the username box.
        String typed = "my.secret-password";

        assertThat(login(typed, "anything at all").getStatus()).isEqualTo(401);

        assertThat(added()).singleElement().satisfies(entry -> {
            assertThat(entry.event()).isEqualTo("auth.login_failed");
            assertThat(entry.actor()).isEqualTo(AuditLog.UNKNOWN_USER);
            assertThat(entry.data().toString()).doesNotContain(typed);
        });
    }

    @Test
    void signupLoginAndLogoutAreRecorded() throws Exception {
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + USER + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isCreated());
        Cookie refresh = login(USER, PASSWORD).getCookie(AuthCookies.REFRESH_TOKEN);
        mvc.perform(post("/api/auth/logout").cookie(refresh)).andExpect(status().isNoContent());

        assertThat(added()).extracting(AuditLog.Entry::event).containsExactly("auth.signup", "auth.login", "auth.logout");
        assertThat(added()).extracting(AuditLog.Entry::actor).containsOnly(USER);
    }

    @Test
    void reusingARefreshTokenIsRecordedEvenThoughTheRequestIsRefused() throws Exception {
        createUser(USER, Role.VIEWER);
        Cookie refresh = login(USER, PASSWORD).getCookie(AuthCookies.REFRESH_TOKEN);
        mvc.perform(post("/api/auth/refresh").cookie(refresh)).andExpect(status().isNoContent());

        mvc.perform(post("/api/auth/refresh").cookie(refresh)).andExpect(status().isUnauthorized());

        assertThat(added()).extracting(AuditLog.Entry::event).containsExactly("auth.login", "auth.session_reuse");
    }

    @Test
    void aRoleChangeRecordsWhoDidItAndWhatChanged() throws Exception {
        createUser("audit.admin", Role.ADMIN);
        createUser(USER, Role.VIEWER);
        Long id = users.findByUsername(USER).orElseThrow().getId();
        Cookie admin = login("audit.admin", PASSWORD).getCookie(AuthCookies.ACCESS_TOKEN);

        mvc.perform(put("/api/admin/users/" + id + "/role").cookie(admin).contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"ANALYST\"}")).andExpect(status().isOk());

        AuditLog.Entry entry = added().getLast();
        assertThat(entry.event()).isEqualTo("auth.role_changed");
        assertThat(entry.actor()).isEqualTo("audit.admin");
        assertThat(entry.data().get("user").asString()).isEqualTo(USER);
        assertThat(entry.data().get("from").asString()).isEqualTo("VIEWER");
        assertThat(entry.data().get("to").asString()).isEqualTo("ANALYST");
    }

    @Test
    void aReservedActorNameCannotBeTakenAtSignup() throws Exception {
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + AuditLog.SYSTEM + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void entriesFromManyThreadsAtOnceStillFormOneChain() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> running = IntStream.range(0, 40).<Future<?>>mapToObj(i -> pool.submit(
                    () -> audit.record(AuditLog.SYSTEM, "test.concurrent", null, Map.of("n", String.valueOf(i))))).toList();
            for (Future<?> one : running) {
                one.get();   // rethrows if an entry could not be added
            }
        } finally {
            pool.shutdown();
        }

        assertThat(added()).hasSize(40);
        assertThat(audit.verify().valid()).isTrue();
    }

    @Test
    void theHeadGoesToTheLogAfterACommitAndNotAfterARollback(CapturedOutput output) {
        transactions.executeWithoutResult(tx -> {
            audit.record(AuditLog.SYSTEM, "test.rolled_back", null, Map.of());
            tx.setRollbackOnly();
        });

        assertThat(lastSeq()).isEqualTo(before);
        assertThat(output.getOut()).doesNotContain("Audit head: seq=" + (before + 1));

        audit.record(AuditLog.SYSTEM, "test.committed", null, Map.of());

        AuditLog.Entry entry = audit.recent(1).getFirst();
        assertThat(entry.seq()).isEqualTo(before + 1);
        assertThat(output.getOut()).contains("Audit head: seq=" + entry.seq() + " hash=" + entry.hash());
    }
}
