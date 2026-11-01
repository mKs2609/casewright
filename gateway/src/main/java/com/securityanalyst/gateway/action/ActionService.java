package com.securityanalyst.gateway.action;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.common.ApiException;
import com.securityanalyst.gateway.evidence.EvidenceService;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Proposed actions and their lifecycle (step 15, ADR-47). Low-risk actions run at once; high-risk
 * ones wait as pending until a person approves or rejects them, or until they expire. Running an
 * action is simulated: it writes a row to `enforcement` (ADR-13). Every step goes in the audit log.
 */
@Service
public class ActionService {

    private static final Logger log = LoggerFactory.getLogger(ActionService.class);
    private static final String SELECT = """
            SELECT a.id, a.incident_id, a.action, a.target, a.risk, a.status, a.evidence, u.username AS decided_by,
                   a.decided_at, a.expires_at, a.created_at
            FROM actions a LEFT JOIN app_users u ON u.id = a.decided_by
            """;

    /** One proposal as the agent sent it. Not trusted until ActionPolicy has checked it. */
    public record Proposal(String action, String target, String evidence) {
    }

    /** An action as the API shows it. */
    public record View(Long id, Long incidentId, String action, String target, String risk, String status,
            String evidence, String decidedBy, Instant decidedAt, Instant expiresAt, Instant createdAt) {
    }

    private final JdbcTemplate jdbc;
    private final AuditLog audit;
    private final EvidenceService evidence;
    private final JsonMapper json;
    private final Duration approvalLifetime;
    private final List<String> protectedDomains;

    public ActionService(JdbcTemplate jdbc, AuditLog audit, EvidenceService evidence, JsonMapper json,
            @Value("${actions.approval-lifetime}") Duration approvalLifetime,
            @Value("${actions.protected-domains}") List<String> protectedDomains) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.evidence = evidence;
        this.json = json;
        this.approvalLifetime = approvalLifetime;
        this.protectedDomains = protectedDomains;
    }

    /**
     * Checks the agent's proposals and saves the allowed ones. A refused proposal is recorded and
     * dropped; the verdict stands, so a bad proposal cannot hide what the investigation found.
     *
     * @return how many are now waiting for a person
     */
    @Transactional
    public int apply(Long incidentId, List<Proposal> proposals, String finalVerdict, String subject, String payloadJson) {
        ActionPolicy.Context context = contextFor(incidentId, finalVerdict, subject, payloadJson);
        Set<String> seen = new HashSet<>();
        int pending = 0;
        for (Proposal proposal : proposals) {
            if (!seen.add(proposal.action() + "\n" + proposal.target())) {
                continue;
            }
            String refusal = ActionPolicy.refusal(proposal.action(), proposal.target(), proposal.evidence(), context);
            if (refusal != null) {
                log.warn("Incident {}: a proposed {} was refused: {}", incidentId, proposal.action(), refusal);
                // The target stays out: a refused one may be anything the agent chose to send.
                audit.record(AuditLog.AGENT, "action.refused", incidentId,
                        Map.of("action", proposal.action(), "reason", refusal));
                continue;
            }
            String risk = ActionPolicy.risk(proposal.action());
            if ("low".equals(risk)) {
                Long id = insert(incidentId, proposal, risk, "executed", null);
                enforce(id, proposal.action(), proposal.target());
                audit.record(AuditLog.SYSTEM, "action.executed", incidentId,
                        Map.of("action", proposal.action(), "target", proposal.target()));
            } else {
                insert(incidentId, proposal, risk, "pending", Instant.now().plus(approvalLifetime));
                audit.record(AuditLog.AGENT, "action.proposed", incidentId,
                        Map.of("action", proposal.action(), "target", proposal.target()));
                pending++;
            }
        }
        return pending;
    }

    /**
     * A person approves or rejects a pending action.
     * noRollbackFor: a decision that comes too late is refused, but noting the expiry must still be saved.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public View decide(Long id, boolean approve, AuthenticatedUser user) {
        View action = find(id);
        if ("expired".equals(action.status())) {
            throw new ApiException(HttpStatus.CONFLICT, "This action has expired");
        }
        if (!"pending".equals(action.status())) {
            throw new ApiException(HttpStatus.CONFLICT, "This action has already been decided");
        }
        if (ActionPolicy.IDENTITY_ACTIONS.contains(action.action()) && action.target().equals(user.username())) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You cannot decide an action on your own account");
        }
        if (action.expiresAt().isBefore(Instant.now())) {
            expireDue();
            throw new ApiException(HttpStatus.CONFLICT, "This action has expired");
        }
        // Only one decision can win: the update counts only if the action is still pending.
        int updated = jdbc.update("UPDATE actions SET status = ?, decided_by = ?, decided_at = now() "
                + "WHERE id = ? AND status = 'pending'", approve ? "executed" : "rejected", user.id(), id);
        if (updated == 0) {
            throw new ApiException(HttpStatus.CONFLICT, "This action has already been decided");
        }
        if (approve) {
            enforce(id, action.action(), action.target());
        }
        audit.record(user.username(), approve ? "action.approved" : "action.rejected", action.incidentId(),
                Map.of("action", action.action(), "target", action.target()));
        settleIncident(action.incidentId());
        return find(id);
    }

    /** Marks everything past its deadline as expired. Runs regularly, and whenever a late decision arrives. */
    @Scheduled(fixedDelayString = "${actions.expiry-check-interval}")
    @Transactional
    public void expireDue() {
        record Expired(Long incidentId, String action, String target) {
        }
        List<Expired> expired = jdbc.query("""
                UPDATE actions SET status = 'expired', decided_at = now()
                WHERE status = 'pending' AND expires_at < now()
                RETURNING incident_id, action, target""",
                (rs, row) -> new Expired(rs.getLong("incident_id"), rs.getString("action"), rs.getString("target")));
        for (Expired one : expired) {
            audit.record(AuditLog.SYSTEM, "action.expired", one.incidentId(),
                    Map.of("action", one.action(), "target", one.target()));
            settleIncident(one.incidentId());
        }
    }

    @Transactional(readOnly = true)
    public List<View> forIncident(Long incidentId) {
        return jdbc.query(SELECT + " WHERE a.incident_id = ? ORDER BY a.id", this::view, incidentId);
    }

    @Transactional(readOnly = true)
    public List<View> withStatus(String status, int limit) {
        return jdbc.query(SELECT + " WHERE a.status = ? ORDER BY a.id DESC LIMIT ?", this::view, status, limit);
    }

    /** When nothing is left waiting, the incident moves on from awaiting_approval. */
    private void settleIncident(Long incidentId) {
        int moved = jdbc.update("""
                UPDATE incidents SET status = 'needs_review'
                WHERE id = ? AND status = 'awaiting_approval'
                  AND NOT EXISTS (SELECT 1 FROM actions WHERE incident_id = ? AND status = 'pending')""",
                incidentId, incidentId);
        if (moved > 0) {
            audit.record(AuditLog.SYSTEM, "incident.status", incidentId, Map.of("status", "needs_review"));
        }
    }

    private View find(Long id) {
        return jdbc.query(SELECT + " WHERE a.id = ?", this::view, id).stream().findFirst()
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Action not found"));
    }

    private Long insert(Long incidentId, Proposal proposal, String risk, String status, Instant expiresAt) {
        return jdbc.queryForObject("""
                INSERT INTO actions (incident_id, action, target, risk, status, evidence, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id""", Long.class, incidentId, proposal.action(),
                proposal.target(), risk, status, proposal.evidence(), expiresAt == null ? null : Timestamp.from(expiresAt));
    }

    private void enforce(Long actionId, String action, String target) {
        jdbc.update("INSERT INTO enforcement (action_id, action, target) VALUES (?, ?, ?)", actionId, action, target);
        log.info("Enforcement (simulated): {} on action {}", action, actionId);
    }

    /** What the proposals are checked against: only what the gateway itself stored. */
    private ActionPolicy.Context contextFor(Long incidentId, String finalVerdict, String subject, String payloadJson) {
        JsonNode payload = json.readTree(payloadJson);
        Set<String> identities = new HashSet<>(Set.of(subject));
        payload.path("events").valueStream().filter(e -> e.hasNonNull("username"))
                .forEach(e -> identities.add(e.get("username").asString()));
        Map<String, Set<String>> indicators = new HashMap<>();
        jdbc.query("SELECT type, value FROM incident_indicators WHERE incident_id = ?", rs -> {
            indicators.computeIfAbsent(rs.getString("type"), t -> new HashSet<>()).add(rs.getString("value"));
        }, incidentId);
        return new ActionPolicy.Context(finalVerdict, identities, indicators, text(payload, "sender"),
                text(payload, "callerNumber"), evidence.recordedSignals(incidentId), evidence.acceptedLabels(incidentId),
                protectedDomains);
    }

    private static String text(JsonNode payload, String field) {
        return payload.hasNonNull(field) ? payload.get(field).asString() : null;
    }

    private View view(ResultSet rs, int row) throws SQLException {
        return new View(rs.getLong("id"), rs.getLong("incident_id"), rs.getString("action"), rs.getString("target"),
                rs.getString("risk"), rs.getString("status"), rs.getString("evidence"), rs.getString("decided_by"),
                instant(rs, "decided_at"), instant(rs, "expires_at"), instant(rs, "created_at"));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
}
