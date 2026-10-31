package com.securityanalyst.gateway.audit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The tamper-evident history (ADR-11, ADR-46). Each entry's hash is an HMAC over the entry and
 * the previous entry's hash, so changing or removing an entry breaks the chain from there on,
 * and without the key (AUDIT_HMAC_KEY, never in the database) a chain cannot be rewritten.
 *
 * {@link #record} joins the caller's transaction, so an action and its entry are saved together
 * or not at all. The chain cannot show the newest entries being cut off the end, because nothing
 * comes after them, so the latest entry number and hash also go to the log file after each commit.
 */
@Service
public class AuditLog {

    /** Who acted, when it was not a logged-in user. Usernames cannot contain parentheses, so nobody can sign up as one. */
    public static final String SYSTEM = "(system)";
    public static final String AGENT = "(agent)";
    public static final String UNKNOWN_USER = "(unknown user)";

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);
    private static final String HMAC = "HmacSHA256";
    private static final int MIN_KEY_BYTES = 32;
    /** Names the one lock that makes adding to the chain one-at-a-time. Any fixed number no other code uses. */
    private static final long CHAIN_LOCK = 7_240_014L;
    private static final int VERIFY_PAGE = 1000;
    private static final String COLUMNS = "seq, ts, actor, event, incident_id, data::text AS data_text, prev_hash, hash";

    /** The "previous hash" of the very first entry. */
    static final String START = "0".repeat(64);

    /** An entry as the API shows it. */
    public record Entry(long seq, Instant ts, String actor, String event, Long incidentId, JsonNode data,
            String prevHash, String hash) {
    }

    /** The result of walking the chain. brokenAt and problem are set only when valid is false. */
    public record Verification(boolean valid, long entries, Long headSeq, String headHash, Long brokenAt,
            String problem) {
    }

    private final JdbcTemplate jdbc;
    private final JsonMapper json;
    private final SecretKeySpec key;

    public AuditLog(JdbcTemplate jdbc, JsonMapper json, @Value("${security.audit.hmac-key}") String base64Key) {
        this.jdbc = jdbc;
        this.json = json;
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("AUDIT_HMAC_KEY must be Base64", e);
        }
        if (raw.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("AUDIT_HMAC_KEY must be at least " + MIN_KEY_BYTES + " bytes");
        }
        this.key = new SecretKeySpec(raw, HMAC);
    }

    /** Adds one entry. data holds short facts only, never incident text or anything the agent wrote. */
    @Transactional
    public void record(String actor, String event, Long incidentId, Map<String, String> data) {
        // Held until this transaction ends, so two entries can never build on the same previous one.
        jdbc.query("SELECT pg_advisory_xact_lock(?)", rs -> { }, CHAIN_LOCK);
        List<Map<String, Object>> last = jdbc.queryForList("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1");
        long seq = last.isEmpty() ? 1 : ((Number) last.getFirst().get("seq")).longValue() + 1;
        String previous = last.isEmpty() ? START : (String) last.getFirst().get("hash");
        // Microseconds: all the database stores, so the time read back is exactly the time hashed.
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MICROS);
        TreeMap<String, String> sorted = new TreeMap<>(data);

        String hash = hash(seq, ts, actor, event, incidentId, sorted, previous);
        jdbc.update("""
                INSERT INTO audit_log (seq, ts, actor, event, incident_id, data, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?)""",
                seq, Timestamp.from(ts), actor, event, incidentId, json.writeValueAsString(sorted), previous, hash);

        // After the commit: an entry that is rolled back was never part of the chain.
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.info("Audit head: seq={} hash={}", seq, hash);
            }
        });
    }

    /** The newest entries, newest first. */
    @Transactional(readOnly = true)
    public List<Entry> recent(int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM audit_log ORDER BY seq DESC LIMIT ?", this::entry, limit);
    }

    /** Walks the whole chain from the first entry and stops at the first problem. */
    @Transactional(readOnly = true)
    public Verification verify() {
        long expectedSeq = 1;
        String previous = START;
        while (true) {
            List<Stored> page = jdbc.query("SELECT " + COLUMNS + " FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT ?",
                    this::stored, expectedSeq, VERIFY_PAGE);
            for (Stored entry : page) {
                String problem = problemWith(entry, expectedSeq, previous);
                if (problem != null) {
                    return new Verification(false, expectedSeq - 1, expectedSeq > 1 ? expectedSeq - 1 : null,
                            expectedSeq > 1 ? previous : null, entry.seq(), problem);
                }
                previous = entry.hash();
                expectedSeq++;
            }
            if (page.size() < VERIFY_PAGE) {
                long entries = expectedSeq - 1;
                return new Verification(true, entries, entries > 0 ? entries : null, entries > 0 ? previous : null, null, null);
            }
        }
    }

    private String problemWith(Stored entry, long expectedSeq, String previous) {
        if (entry.seq() != expectedSeq) {
            return "Entry " + expectedSeq + " is missing";
        }
        if (!entry.prevHash().equals(previous)) {
            return "Entry " + entry.seq() + " does not follow the entry before it";
        }
        String computed = hash(entry.seq(), entry.ts(), entry.actor(), entry.event(), entry.incidentId(), entry.data(),
                entry.prevHash());
        boolean same = MessageDigest.isEqual(computed.getBytes(StandardCharsets.UTF_8),
                entry.hash().getBytes(StandardCharsets.UTF_8));
        return same ? null : "Entry " + entry.seq() + " has been changed";
    }

    /**
     * The HMAC of one entry. It is written as a JSON array so that field boundaries are
     * unambiguous, and data is sorted because the database does not keep the original key order.
     */
    private String hash(long seq, Instant ts, String actor, String event, Long incidentId, TreeMap<String, String> data,
            String previous) {
        String canonical = json.writeValueAsString(Arrays.asList(seq, ts.toString(), actor, event, incidentId, data, previous));
        try {
            Mac mac = Mac.getInstance(HMAC);   // a new one each time: a Mac cannot be shared between threads
            mac.init(key);
            return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Stored(long seq, Instant ts, String actor, String event, Long incidentId, TreeMap<String, String> data,
            String prevHash, String hash) {
    }

    private Stored stored(ResultSet rs, int row) throws SQLException {
        TreeMap<String, String> data = new TreeMap<>();
        json.readTree(rs.getString("data_text")).properties().forEach(e -> data.put(e.getKey(), e.getValue().asString()));
        return new Stored(rs.getLong("seq"), rs.getTimestamp("ts").toInstant(), rs.getString("actor"), rs.getString("event"),
                rs.getObject("incident_id", Long.class), data, rs.getString("prev_hash"), rs.getString("hash"));
    }

    private Entry entry(ResultSet rs, int row) throws SQLException {
        return new Entry(rs.getLong("seq"), rs.getTimestamp("ts").toInstant(), rs.getString("actor"), rs.getString("event"),
                rs.getObject("incident_id", Long.class), json.readTree(rs.getString("data_text")),
                rs.getString("prev_hash"), rs.getString("hash"));
    }
}
