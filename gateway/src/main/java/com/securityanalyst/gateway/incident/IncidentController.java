package com.securityanalyst.gateway.incident;

import java.net.URI;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.auth.AuthenticatedUser;

import jakarta.validation.Valid;

/**
 * Incidents. Submitting needs ANALYST or ADMIN (enforced in SecurityConfig);
 * any logged-in user may read them.
 */
@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private final IncidentService incidents;

    public IncidentController(IncidentService incidents) {
        this.incidents = incidents;
    }

    /**
     * 202 Accepted, not 201 Created: the incident is stored, but its investigation has only
     * been queued, not done. The Location header says where to watch it.
     */
    @PostMapping
    public ResponseEntity<IncidentResponses.Detail> submit(@Valid @RequestBody IncidentRequest request,
            @AuthenticationPrincipal AuthenticatedUser user) {
        IncidentResponses.Detail created = incidents.submit(request, user);
        return ResponseEntity.accepted().location(URI.create("/api/incidents/" + created.id())).body(created);
    }

    /** The newest 100 incidents, newest first. */
    @GetMapping
    public List<IncidentResponses.Summary> list() {
        return incidents.latest();
    }

    @GetMapping("/{id}")
    public IncidentResponses.Detail get(@PathVariable Long id) {
        return incidents.get(id);
    }
}
