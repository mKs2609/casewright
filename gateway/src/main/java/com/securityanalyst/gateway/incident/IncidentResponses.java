package com.securityanalyst.gateway.incident;

import java.time.Instant;
import java.util.List;

import com.securityanalyst.gateway.action.ActionService;
import com.securityanalyst.gateway.evidence.EvidenceService;
import com.securityanalyst.gateway.verdict.VerdictService;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** What the incident endpoints send back. Built from the entity, never the entity itself. */
public final class IncidentResponses {

    private IncidentResponses() {
    }

    /** One line in the incident list: no payload, so the list stays small. The verdict and score are null until there is a verdict. */
    record Summary(Long id, String kind, String subjectIdentity, String subjectName, String status,
            String source, String createdBy, Instant createdAt, String verdict, Integer riskScore) {

        static Summary from(Incident incident, VerdictService.Outcome outcome) {
            return new Summary(incident.getId(), incident.getKind(), incident.getSubject().getIdentity(),
                    incident.getSubject().getDisplayName(), incident.getStatus(), incident.getSource(),
                    incident.getCreatedBy().getUsername(), incident.getCreatedAt(),
                    outcome == null ? null : outcome.verdict(), outcome == null ? null : outcome.riskScore());
        }
    }

    /**
     * One incident in full: what was submitted (as a JSON object, not a string), the
     * evidence gathered so far, in order (E1, E2, ... and any refused calls R1, R2, ...), and
     * the verdict once the investigation has finished (null until then), and its actions.
     */
    public record Detail(Long id, String kind, String subjectIdentity, String subjectName, String status,
            String source, String createdBy, Instant createdAt, JsonNode payload, List<EvidenceService.View> evidence,
            VerdictService.View verdict, List<ActionService.View> actions) {

        static Detail from(Incident incident, JsonMapper json, List<EvidenceService.View> evidence,
                VerdictService.View verdict, List<ActionService.View> actions) {
            Summary s = Summary.from(incident, null);
            return new Detail(s.id(), s.kind(), s.subjectIdentity(), s.subjectName(), s.status(), s.source(),
                    s.createdBy(), s.createdAt(), json.readTree(incident.getPayload()), evidence, verdict, actions);
        }
    }
}
