package com.securityanalyst.gateway.demo;

import java.net.URI;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.common.ApiException;
import com.securityanalyst.gateway.incident.Incident;
import com.securityanalyst.gateway.incident.IncidentResponses;
import com.securityanalyst.gateway.incident.IncidentService;

/**
 * The demo buttons (FR-26). Any logged-in user may list them; firing one needs ANALYST or
 * ADMIN (SecurityConfig), because it submits an incident.
 *
 * The browser only names a scenario. It sends no body, and none is read: what is submitted is
 * the gateway's own copy, through the same path as POST /api/incidents, marked as a demo.
 * Switched off with demo.enabled=false, and then these URLs do not exist.
 */
@RestController
@RequestMapping("/api/demo")
@ConditionalOnProperty(name = "demo.enabled", havingValue = "true")
public class DemoController {

    private final DemoScenarios scenarios;
    private final IncidentService incidents;

    public DemoController(DemoScenarios scenarios, IncidentService incidents) {
        this.scenarios = scenarios;
        this.incidents = incidents;
    }

    @GetMapping("/scenarios")
    public List<DemoScenarios.Scenario> scenarios() {
        return scenarios.list();
    }

    /** 202 Accepted, like POST /api/incidents: stored, and the investigation has started. */
    @PostMapping("/{scenario}")
    public ResponseEntity<IncidentResponses.Detail> run(@PathVariable String scenario,
            @AuthenticationPrincipal AuthenticatedUser user) {
        var request = scenarios.incident(scenario)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "There is no demo scenario with that name"));
        IncidentResponses.Detail created = incidents.submit(request, user, Incident.SOURCE_DEMO);
        return ResponseEntity.accepted().location(URI.create("/api/incidents/" + created.id())).body(created);
    }
}
