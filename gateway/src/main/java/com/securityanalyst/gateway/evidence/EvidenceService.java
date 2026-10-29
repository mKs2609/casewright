package com.securityanalyst.gateway.evidence;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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

    /** One finding as stored: its kind and weight. */
    public record Finding(String id, int weight) {
    }

    /** Every finding of the incident's accepted evidence, as stored (what the risk score is recomputed from). */
    @Transactional(readOnly = true)
    public List<Finding> findings(Long incidentId) {
        return evidence.findByIncidentIdOrderByIdAsc(incidentId).stream()
                .filter(e -> Evidence.OK.equals(e.getStatus()))
                .flatMap(e -> json.readTree(e.getSignals()).valueStream())
                .map(signal -> new Finding(signal.get("id").asString(), signal.get("weight").asInt()))
                .toList();
    }

    /** One finding as stored, with the evidence item it belongs to and its exact words. */
    public record RecordedSignal(String evidence, String id, String label, String plain, int weight, String mitre) {
    }

    /** Every finding of the incident's accepted evidence, as stored (what reports are checked against). */
    @Transactional(readOnly = true)
    public List<RecordedSignal> recordedSignals(Long incidentId) {
        return evidence.findByIncidentIdOrderByIdAsc(incidentId).stream()
                .filter(e -> Evidence.OK.equals(e.getStatus()))
                .flatMap(e -> json.readTree(e.getSignals()).valueStream().map(signal -> new RecordedSignal(e.getLabel(),
                        signal.get("id").asString(), signal.get("label").asString(), signal.get("plain").asString(),
                        signal.get("weight").asInt(), signal.hasNonNull("mitre") ? signal.get("mitre").asString() : null)))
                .toList();
    }

    /** The labels of the incident's accepted evidence (E1, E2, ...). */
    @Transactional(readOnly = true)
    public Set<String> acceptedLabels(Long incidentId) {
        return evidence.findByIncidentIdOrderByIdAsc(incidentId).stream()
                .filter(e -> Evidence.OK.equals(e.getStatus()))
                .map(Evidence::getLabel)
                .collect(Collectors.toSet());
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
