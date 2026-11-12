package com.securityanalyst.gateway.incident;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.action.ActionService;
import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.common.ApiException;
import com.securityanalyst.gateway.common.TooManyRequestsException;
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
    private final ActionService actions;
    /** Most demo and red-team runs per day (UTC), for the whole site; 0 for no limit (step 19b). */
    private final int maxDemoRunsPerDay;

    public IncidentService(IncidentRepository incidents, MonitoredIdentityService identities, UserRepository users,
            JsonMapper json, ApplicationEventPublisher events, EvidenceService evidence, VerdictService verdicts,
            AuditLog audit, ActionService actions, @Value("${demo.max-runs-per-day}") int maxDemoRunsPerDay) {
        this.maxDemoRunsPerDay = maxDemoRunsPerDay;
        this.incidents = incidents;
        this.identities = identities;
        this.users = users;
        this.json = json;
        this.events = events;
        this.evidence = evidence;
        this.verdicts = verdicts;
        this.audit = audit;
        this.actions = actions;
    }

    /**
     * source: where the incident came from, Incident.SOURCE_API or SOURCE_DEMO. One method only, called
     * from outside: a call from inside this class would skip Spring's proxy, and with it the transaction.
     */
    @Transactional
    public IncidentResponses.Detail submit(IncidentRequest request, AuthenticatedUser submittedBy, String source) {
        refuseDemoRunsOverTodaysLimit(source);
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
        Incident incident = new Incident(kind, subject, payload, source, users.getReferenceById(submittedBy.id()));
        Incident saved = incidents.saveAndFlush(incident);
        audit.record(submittedBy.username(), "incident.submitted", saved.getId(),
                Map.of("kind", kind, "subject", subject.getIdentity(), "source", source));
        // Starts the investigation, but only once this transaction has committed (InvestigationRunner).
        events.publishEvent(new IncidentSubmitted(saved.getId()));
        return IncidentResponses.Detail.from(saved, json, List.of(), null, List.of());
    }

    private static final List<String> DEMO_SOURCES = List.of(Incident.SOURCE_DEMO, Incident.SOURCE_RED_TEAM);

    /**
     * Each demo run stores an incident for good (the audit log cannot be cleaned, ADR-46), so the
     * public demo has a daily ceiling on top of the per-address rate limit. Counted from the stored
     * incidents, so restarting the gateway does not reset it. Two runs arriving at the same instant
     * can each pass the count; the ceiling guards against filling the disk, it is not an exact quota.
     */
    private void refuseDemoRunsOverTodaysLimit(String source) {
        if (maxDemoRunsPerDay <= 0 || !DEMO_SOURCES.contains(source)) {
            return;
        }
        Instant startOfToday = LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        if (incidents.countBySourceInAndCreatedAtGreaterThanEqual(DEMO_SOURCES, startOfToday) >= maxDemoRunsPerDay) {
            Duration untilTomorrow = Duration.between(Instant.now(), startOfToday.plus(Duration.ofDays(1)));
            throw new TooManyRequestsException("The demo has reached today's limit. Try again tomorrow.", untilTomorrow);
        }
    }

    @Transactional(readOnly = true)
    public List<IncidentResponses.Summary> latest() {
        List<Incident> newest = incidents.findTop100ByOrderByCreatedAtDescIdDesc();
        Map<Long, VerdictService.Outcome> outcomes = verdicts.outcomes(newest.stream().map(Incident::getId).toList());
        return newest.stream().map(i -> IncidentResponses.Summary.from(i, outcomes.get(i.getId()))).toList();
    }

    /** What an investigation needs to know about one incident. */
    public record InvestigationInput(Long id, String kind, String subjectIdentity, String payloadJson, String source) {
    }

    @Transactional(readOnly = true)
    public InvestigationInput investigationInput(Long id) {
        Incident incident = incidents.findWithDetailsById(id)
                .orElseThrow(() -> new IllegalStateException("Incident " + id + " does not exist"));
        return new InvestigationInput(incident.getId(), incident.getKind(), incident.getSubject().getIdentity(),
                incident.getPayload(), incident.getSource());
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
                        verdicts.forIncident(id).orElse(null), actions.forIncident(id)))
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Incident not found"));
    }
}
