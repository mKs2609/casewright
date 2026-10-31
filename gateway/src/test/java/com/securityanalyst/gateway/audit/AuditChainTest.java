package com.securityanalyst.gateway.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;

import jakarta.servlet.http.Cookie;
import tools.jackson.databind.json.JsonMapper;

/**
 * The chain itself. @Transactional: everything here, the tampering included, is rolled back after
 * each test (PostgreSQL can undo even the switched-off trigger), because every test class shares
 * this database and a chain broken for real would fail them all.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditChainTest extends PostgresIntegrationTest {

    @Autowired
    private AuditLog audit;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private JsonMapper json;
    @Autowired
    private MockMvc mvc;

    private long first;
    private long middle;
    private long last;

    @BeforeEach
    void addThreeEntries() {
        audit.record("asha.rao", "test.first", 5L, Map.of("a", "1"));
        audit.record(AuditLog.SYSTEM, "test.second", null, Map.of());
        audit.record("asha.rao", "test.third", 5L, Map.of("b", "2"));
        last = audit.recent(1).getFirst().seq();
        middle = last - 1;
        first = last - 2;
    }

    /** What someone with full database access could do: switch the trigger off, then edit. */
    private void tamper(String sql, Object... args) {
        jdbc.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change");
        jdbc.update(sql, args);
    }

    private void assertBroken(long at, String problem) {
        AuditLog.Verification result = audit.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.brokenAt()).isEqualTo(at);
        assertThat(result.problem()).isEqualTo(problem);
    }

    @Test
    void eachEntryBuildsOnTheOneBefore() {
        List<AuditLog.Entry> entries = audit.recent(3);   // newest first

        assertThat(entries).extracting(AuditLog.Entry::event).containsExactly("test.third", "test.second", "test.first");
        assertThat(entries).extracting(AuditLog.Entry::seq).containsExactly(last, middle, first);
        assertThat(entries.get(0).prevHash()).isEqualTo(entries.get(1).hash());
        assertThat(entries.get(1).prevHash()).isEqualTo(entries.get(2).hash());
        assertThat(entries.get(0).hash()).hasSize(64).isNotEqualTo(entries.get(1).hash());
    }

    @Test
    void anUntouchedChainVerifies() {
        AuditLog.Verification result = audit.verify();

        assertThat(result.valid()).isTrue();
        assertThat(result.entries()).isEqualTo(last);
        assertThat(result.headSeq()).isEqualTo(last);
        assertThat(result.headHash()).isEqualTo(audit.recent(1).getFirst().hash());
        assertThat(result.brokenAt()).isNull();
        assertThat(result.problem()).isNull();
    }

    @Test
    void dataVerifiesWhateverOrderTheDatabaseKeepsItsKeysIn() {
        // JSONB reorders keys (shortest first), so the hash must not depend on the order.
        audit.record("asha.rao", "test.keys", null, Map.of("zzzz", "1", "a", "2", "mm", "3"));

        assertThat(audit.verify().valid()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "actor = 'someone.else'",
            "event = 'test.harmless'",
            "incident_id = 6",
            "ts = ts + interval '1 second'",
            "data = '{\"a\":\"2\"}'",
            "hash = repeat('a', 64)" })
    void changingAnyFieldIsCaughtAtThatEntry(String change) {
        tamper("UPDATE audit_log SET " + change + " WHERE seq = ?", first);

        assertBroken(first, "Entry " + first + " has been changed");
    }

    @Test
    void anEntryThatNoLongerFollowsTheOneBeforeIsCaught() {
        tamper("UPDATE audit_log SET prev_hash = repeat('b', 64) WHERE seq = ?", middle);

        assertBroken(middle, "Entry " + middle + " does not follow the entry before it");
    }

    @Test
    void aMissingEntryIsCaught() {
        tamper("DELETE FROM audit_log WHERE seq = ?", middle);

        assertBroken(last, "Entry " + middle + " is missing");
    }

    @Test
    void removingEverythingFromTheStartIsCaught() {
        tamper("DELETE FROM audit_log WHERE seq < ?", last);

        assertBroken(last, "Entry 1 is missing");
    }

    @Test
    void anEntryAddedWithoutTheKeyIsCaught() {
        // Someone with full database access, and this code, but not the key.
        String otherKey = Base64.getEncoder().encodeToString("an-attacker-chosen-key-of-32-byt".getBytes());
        new AuditLog(jdbc, json, otherKey).record("asha.rao", "test.forged", null, Map.of());

        assertBroken(last + 1, "Entry " + (last + 1) + " has been changed");
    }

    @Test
    void swappingInAValidlySignedEntryFromAnotherVersionOfHistoryIsCaught() {
        // Someone holds a properly signed entry with the same number (from a backup, say) and
        // re-links the next entry to it. Only the previous hash inside each signature stops this.
        audit.record("asha.rao", "test.old_version", null, Map.of());
        long swapped = last + 1;
        Map<String, Object> old = jdbc.queryForMap("SELECT event, ts, hash FROM audit_log WHERE seq = ?", swapped);
        tamper("DELETE FROM audit_log WHERE seq = ?", swapped);

        audit.record("asha.rao", "test.new_version", null, Map.of());
        audit.record("asha.rao", "test.next", null, Map.of());
        tamper("UPDATE audit_log SET event = ?, ts = ?, hash = ? WHERE seq = ?", old.get("event"), old.get("ts"),
                old.get("hash"), swapped);
        tamper("UPDATE audit_log SET prev_hash = ? WHERE seq = ?", old.get("hash"), swapped + 1);

        assertBroken(swapped + 1, "Entry " + (swapped + 1) + " has been changed");
    }

    @Test
    void cuttingOffTheNewestEntriesIsWhatTheChainAloneCannotSee() {
        // The limit the head line in the log file is there for: the chain still verifies,
        // but it reports a head older than the last one the log saw.
        tamper("DELETE FROM audit_log WHERE seq = ?", last);

        AuditLog.Verification result = audit.verify();
        assertThat(result.valid()).isTrue();
        assertThat(result.headSeq()).isEqualTo(middle);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UPDATE audit_log SET actor = 'someone.else'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log" })
    void theDatabaseItselfRefusesToChangeTheLog(String sql) {
        assertThatThrownBy(() -> jdbc.execute(sql))
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("append-only");
    }

    @Test
    void aMissingOrShortKeyStopsTheApplication() {
        assertThatThrownBy(() -> new AuditLog(jdbc, json, Base64.getEncoder().encodeToString(new byte[31])))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("at least 32 bytes");
        assertThatThrownBy(() -> new AuditLog(jdbc, json, "not base64!"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Base64");
    }

    // ------------------------------------------------------------------ the API

    private Cookie loggedInViewer() throws Exception {
        String credentials = "{\"username\":\"audit.reader\",\"password\":\"correct horse battery staple\"}";
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(credentials))
                .andExpect(status().isCreated());
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(credentials))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
    }

    @Test
    void anyLoggedInUserCanReadAndVerify() throws Exception {
        Cookie viewer = loggedInViewer();

        // The login itself is the newest entry.
        mvc.perform(get("/api/audit").param("limit", "2").cookie(viewer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].event").value("auth.login"))
                .andExpect(jsonPath("$[0].actor").value("audit.reader"));
        mvc.perform(get("/api/audit/verify").cookie(viewer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void readingNeedsALogin() throws Exception {
        mvc.perform(get("/api/audit")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/audit/verify")).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = { "0", "-1", "501", "lots" })
    void aBadLimitIsRefused(String limit) throws Exception {
        mvc.perform(get("/api/audit").param("limit", limit).cookie(loggedInViewer())).andExpect(status().isBadRequest());
    }

    @Test
    void theApiOffersNoWayToChangeTheLog() throws Exception {
        Cookie viewer = loggedInViewer();

        mvc.perform(post("/api/audit").cookie(viewer)).andExpect(status().isMethodNotAllowed());
        mvc.perform(put("/api/audit").cookie(viewer)).andExpect(status().isMethodNotAllowed());
        mvc.perform(delete("/api/audit").cookie(viewer)).andExpect(status().isMethodNotAllowed());
    }
}
