package com.securityanalyst.gateway.evidence;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Records the evidence chain and reads it back. Each item is saved as soon as it arrives,
 * in its own transaction, so the evidence gathered so far is kept even if the
 * investigation fails later.
 */
@Service
public class EvidenceService {

    /** One evidence item as the API shows it: JSON parts as JSON, not as strings. */
    public record View(String label, String tool, JsonNode args, String status, String summary, JsonNode result,
            JsonNode signals, String reason, Instant createdAt) {
    }

    private final EvidenceRepository evidence;
    private final JsonMapper json;

    public EvidenceService(EvidenceRepository evidence, JsonMapper json) {
        this.evidence = evidence;
        this.json = json;
    }

    @Transactional
    public void recordAccepted(Long incidentId, String label, String tool, Map<String, String> args, String summary,
            JsonNode result, List<?> signals) {
        evidence.save(Evidence.accepted(incidentId, label, tool, json.writeValueAsString(args), summary,
                json.writeValueAsString(result), json.writeValueAsString(signals)));
    }

    @Transactional
    public void recordRejected(Long incidentId, String label, String tool, Map<String, String> args, String reason) {
        evidence.save(Evidence.rejected(incidentId, label, tool, json.writeValueAsString(args), reason));
    }

    @Transactional(readOnly = true)
    public List<View> forIncident(Long incidentId) {
        return evidence.findByIncidentIdOrderByIdAsc(incidentId).stream()
                .map(e -> new View(e.getLabel(), e.getTool(), json.readTree(e.getArgs()), e.getStatus(), e.getSummary(),
                        e.getResult() == null ? null : json.readTree(e.getResult()), json.readTree(e.getSignals()),
                        e.getReason(), e.getCreatedAt()))
                .toList();
    }
}
