package com.securityanalyst.gateway.incident;

import java.util.List;
import java.util.Map;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.common.ApiException;
import com.securityanalyst.gateway.evidence.EvidenceService;
import com.securityanalyst.gateway.identity.MonitoredIdentity;
import com.securityanalyst.gateway.identity.MonitoredIdentityService;
import com.securityanalyst.gateway.verdict.VerdictService;

import tools.jackson.databind.json.JsonMapper;

/** Storing, listing and fetching incidents (the investigation runs in InvestigationRunner). */
@Service
public class IncidentService {

    private final IncidentRepository incidents;
    private final MonitoredIdentityService identities;
    private final UserRepository users;
    private final JsonMapper json;
    private final ApplicationEventPublisher events;
    private final EvidenceService evidence;
    private final VerdictService verdicts;
    private final AuditLog audit;

    public IncidentService(IncidentRepository incidents, MonitoredIdentityService identities, UserRepository users,
            JsonMapper json, ApplicationEventPublisher events, EvidenceService evidence, VerdictService verdicts,
            AuditLog audit) {
        this.incidents = incidents;
        this.identities = identities;
        this.users = users;
        this.json = json;
        this.events = events;
        this.evidence = evidence;
        this.verdicts = verdicts;
        this.audit = audit;
    }

    @Transactional
    public IncidentResponses.Detail submit(IncidentRequest request, AuthenticatedUser submittedBy) {
        MonitoredIdentity subject = identities.find(request.subjectIdentity())
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Unknown monitored identity"));

        // Exhaustive: IncidentRequest is sealed, so the compiler insists every kind is handled here.
        String kind = switch (request) {
            case EmailIncidentRequest email -> "email";
            case LoginIncidentRequest login -> "login";
            case CallTranscriptIncidentRequest call -> "call_transcript";
        };

        // Written as an IncidentRequest so the "kind" field is included in the stored JSON.
        String payload = json.writerFor(IncidentRequest.class).writeValueAsString(request);
        Incident incident = new Incident(kind, subject, payload, Incident.SOURCE_API,
                users.getReferenceById(submittedBy.id()));
        Incident saved = incidents.saveAndFlush(incident);
        audit.record(submittedBy.username(), "incident.submitted", saved.getId(),
                Map.of("kind", kind, "subject", subject.getIdentity()));
        // Starts the investigation, but only once this transaction has committed (InvestigationRunner).
        events.publishEvent(new IncidentSubmitted(saved.getId()));
        return IncidentResponses.Detail.from(saved, json, List.of(), null);
    }

    @Transactional(readOnly = true)
    public List<IncidentResponses.Summary> latest() {
        return incidents.findTop100ByOrderByCreatedAtDescIdDesc().stream().map(IncidentResponses.Summary::from).toList();
    }

    /** What an investigation needs to know about one incident. */
    public record InvestigationInput(Long id, String kind, String subjectIdentity, String payloadJson) {
    }

    @Transactional(readOnly = true)
    public InvestigationInput investigationInput(Long id) {
        Incident incident = incidents.findWithDetailsById(id)
                .orElseThrow(() -> new IllegalStateException("Incident " + id + " does not exist"));
        return new InvestigationInput(incident.getId(), incident.getKind(), incident.getSubject().getIdentity(),
                incident.getPayload());
    }

    /** Moves an incident to a new status. The database refuses any status not in its list. */
    @Transactional
    public void updateStatus(Long id, String status) {
        incidents.updateStatus(id, status);
        audit.record(AuditLog.SYSTEM, "incident.status", id, Map.of("status", status));
    }

    @Transactional(readOnly = true)
    public IncidentResponses.Detail get(Long id) {
        return incidents.findWithDetailsById(id)
                .map(incident -> IncidentResponses.Detail.from(incident, json, evidence.forIncident(id),
                        verdicts.forIncident(id).orElse(null)))
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Incident not found"));
    }
}
