package com.securityanalyst.gateway.redteam;

import java.net.URI;

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
import com.securityanalyst.gateway.demo.DemoScenarios;
import com.securityanalyst.gateway.incident.Incident;
import com.securityanalyst.gateway.incident.IncidentResponses;
import com.securityanalyst.gateway.incident.IncidentService;

/**
 * The red-team probe (FR-27, ADR-51). Starting a run needs ANALYST or ADMIN (SecurityConfig): it
 * submits the prompt-injection demo email as an incident marked red_team, and the investigation
 * runner then asks the agent to play its scripted, hijacked model. Any logged-in user may read a
 * run's scorecard. A demo feature, so it exists only with demo.enabled.
 */
@RestController
@RequestMapping("/api/red-team")
@ConditionalOnProperty(name = "demo.enabled", havingValue = "true")
public class RedTeamController {

    /** The email whose hidden note the hijacked model follows. */
    static final String SCENARIO = "prompt_injection_email";

    private final DemoScenarios scenarios;
    private final IncidentService incidents;

    public RedTeamController(DemoScenarios scenarios, IncidentService incidents) {
        this.scenarios = scenarios;
        this.incidents = incidents;
    }

    /** 202 Accepted: stored, and the run has started. No body is read. */
    @PostMapping
    public ResponseEntity<IncidentResponses.Detail> start(@AuthenticationPrincipal AuthenticatedUser user) {
        var request = scenarios.incident(SCENARIO)
                .orElseThrow(() -> new IllegalStateException("The red-team scenario is missing from the demo scenarios"));
        IncidentResponses.Detail created = incidents.submit(request, user, Incident.SOURCE_RED_TEAM);
        return ResponseEntity.accepted().location(URI.create("/api/incidents/" + created.id())).body(created);
    }

    @GetMapping("/{id}")
    public RedTeamScorecard.Card scorecard(@PathVariable Long id) {
        IncidentResponses.Detail incident = incidents.get(id);
        if (!Incident.SOURCE_RED_TEAM.equals(incident.source())) {
            throw new ApiException(HttpStatus.NOT_FOUND, "That incident is not a red-team run");
        }
        return RedTeamScorecard.of(incident);
    }
}
