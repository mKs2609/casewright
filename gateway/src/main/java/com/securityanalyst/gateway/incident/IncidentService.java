package com.securityanalyst.gateway.incident;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.common.ApiException;
import com.securityanalyst.gateway.identity.MonitoredIdentity;
import com.securityanalyst.gateway.identity.MonitoredIdentityService;

import tools.jackson.databind.json.JsonMapper;

/** Storing, listing and fetching incidents. Investigation itself comes in later steps. */
@Service
public class IncidentService {

    private final IncidentRepository incidents;
    private final MonitoredIdentityService identities;
    private final UserRepository users;
    private final JsonMapper json;

    public IncidentService(IncidentRepository incidents, MonitoredIdentityService identities, UserRepository users,
            JsonMapper json) {
        this.incidents = incidents;
        this.identities = identities;
        this.users = users;
        this.json = json;
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
        return IncidentResponses.Detail.from(incidents.saveAndFlush(incident), json);
    }

    @Transactional(readOnly = true)
    public List<IncidentResponses.Summary> latest() {
        return incidents.findTop100ByOrderByCreatedAtDescIdDesc().stream().map(IncidentResponses.Summary::from).toList();
    }

    @Transactional(readOnly = true)
    public IncidentResponses.Detail get(Long id) {
        return incidents.findWithDetailsById(id)
                .map(incident -> IncidentResponses.Detail.from(incident, json))
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Incident not found"));
    }
}
