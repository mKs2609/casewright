package com.securityanalyst.gateway.verdict;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.evidence.EvidenceService;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Turns the agent's verdict into the incident's outcome, with the score floor applied
 * (AGENT_DESIGN section 8, ADR-9): the gateway recomputes the risk score from the evidence
 * it stored, and the final verdict is never lower than that score's band.
 *
 * - The agent may be MORE cautious than the evidence (its verdict stands).
 * - If it claims less, the verdict is raised to the evidence band.
 * - If it claims benign while the evidence says otherwise, or the two differ by two levels,
 *   that is a disagreement: the incident goes to a human, whatever else is true.
 */
@Service
public class VerdictService {

    /** What the agent said. */
    public record Claim(String verdict, String attackType, int riskScore, List<String> citedEvidence,
            String counterfactual, String engine) {
    }

    /** What was decided, and the status the incident moves to. */
    public record Decision(String verdict, String attackType, int riskScore, boolean disagreement, String status) {
    }

    /** The two reports (step 13), already checked against the evidence by the caller. */
    public record Reports(Object soc, Object plain) {
    }

    /** A verdict as the API shows it. The reports are null for verdicts recorded before step 13. */
    public record View(String verdict, String attackType, int riskScore, String agentVerdict, int agentRiskScore,
            boolean disagreement, String engine, JsonNode citedEvidence, String counterfactual, JsonNode socReport,
            JsonNode plainReport, Instant createdAt) {
    }

    private final EvidenceService evidence;
    private final JdbcTemplate jdbc;
    private final JsonMapper json;

    public VerdictService(EvidenceService evidence, JdbcTemplate jdbc, JsonMapper json) {
        this.evidence = evidence;
        this.jdbc = jdbc;
        this.json = json;
    }

    /**
     * Works out the outcome from the evidence the gateway stored, without saving anything, so
     * the caller can check the reports against the final verdict before {@link #record}.
     */
    @Transactional(readOnly = true)
    public Decision assess(Long incidentId, Claim claim) {
        List<RiskScore.Finding> findings = evidence.findings(incidentId).stream()
                .map(f -> new RiskScore.Finding(f.id(), f.weight())).toList();
        int score = RiskScore.of(findings);
        String band = RiskScore.band(score);

        String verdict = RiskScore.moreSevere(claim.verdict(), band);
        int gap = Math.abs(RiskScore.severity(claim.verdict()) - RiskScore.severity(band));
        boolean disagreement = gap >= 2 || ("benign".equals(claim.verdict()) && !"benign".equals(band));
        // A raised verdict must not keep "no attack" as its type.
        String attackType = !"benign".equals(verdict) && "none".equals(claim.attackType()) ? "other" : claim.attackType();
        String status = disagreement || !"benign".equals(verdict) ? "needs_review" : "closed";
        return new Decision(verdict, attackType, score, disagreement, status);
    }

    @Transactional
    public void record(Long incidentId, Claim claim, Decision decision, Reports reports) {
        jdbc.update("""
                INSERT INTO verdicts (incident_id, verdict, attack_type, risk_score, agent_verdict, agent_risk_score,
                                      disagreement, engine, cited_evidence, counterfactual, soc_report, plain_report)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?::jsonb, ?::jsonb)""",
                incidentId, decision.verdict(), decision.attackType(), decision.riskScore(), claim.verdict(),
                claim.riskScore(), decision.disagreement(), claim.engine(), json.writeValueAsString(claim.citedEvidence()),
                claim.counterfactual(), json.writeValueAsString(reports.soc()), json.writeValueAsString(reports.plain()));
    }

    @Transactional(readOnly = true)
    public Optional<View> forIncident(Long incidentId) {
        return jdbc.query("""
                SELECT verdict, attack_type, risk_score, agent_verdict, agent_risk_score, disagreement, engine,
                       cited_evidence::text AS cited, counterfactual, soc_report::text AS soc,
                       plain_report::text AS plain, created_at
                FROM verdicts WHERE incident_id = ?""",
                (rs, row) -> new View(rs.getString("verdict"), rs.getString("attack_type"), rs.getInt("risk_score"),
                        rs.getString("agent_verdict"), rs.getInt("agent_risk_score"), rs.getBoolean("disagreement"),
                        rs.getString("engine"), json.readTree(rs.getString("cited")), rs.getString("counterfactual"),
                        jsonOrNull(rs.getString("soc")), jsonOrNull(rs.getString("plain")),
                        rs.getTimestamp("created_at").toInstant()),
                incidentId).stream().findFirst();
    }

    private JsonNode jsonOrNull(String text) {
        return text == null ? null : json.readTree(text);
    }
}
