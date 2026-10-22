package com.securityanalyst.gateway.incident;

import java.time.Instant;
import java.util.List;

import com.securityanalyst.gateway.evidence.EvidenceService;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** What the incident endpoints send back. Built from the entity, never the entity itself. */
final class IncidentResponses {

    private IncidentResponses() {
    }

    /** One line in the incident list: no payload, so the list stays small. */
    record Summary(Long id, String kind, String subjectIdentity, String subjectName, String status,
            String source, String createdBy, Instant createdAt) {

        static Summary from(Incident incident) {
            return new Summary(incident.getId(), incident.getKind(), incident.getSubject().getIdentity(),
                    incident.getSubject().getDisplayName(), incident.getStatus(), incident.getSource(),
                    incident.getCreatedBy().getUsername(), incident.getCreatedAt());
        }
    }

    /**
     * One incident in full: what was submitted (as a JSON object, not a string) and the
     * evidence gathered so far, in order (E1, E2, ... and any refused calls R1, R2, ...).
     */
    record Detail(Long id, String kind, String subjectIdentity, String subjectName, String status,
            String source, String createdBy, Instant createdAt, JsonNode payload, List<EvidenceService.View> evidence) {

        static Detail from(Incident incident, JsonMapper json, List<EvidenceService.View> evidence) {
            Summary s = Summary.from(incident);
            return new Detail(s.id(), s.kind(), s.subjectIdentity(), s.subjectName(), s.status(), s.source(),
                    s.createdBy(), s.createdAt(), json.readTree(incident.getPayload()), evidence);
        }
    }
}
