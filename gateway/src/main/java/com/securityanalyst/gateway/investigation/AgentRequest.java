package com.securityanalyst.gateway.investigation;

import java.util.List;

import com.securityanalyst.gateway.identity.Baseline;

import tools.jackson.databind.JsonNode;

/**
 * Everything the agent needs for one investigation, sent with the request (ADR-3: the
 * agent has no database access and remembers nothing between investigations).
 * The baseline is decrypted here, in the gateway, and travels only over this machine.
 * The recent indicators (step 10b) carry values and incident numbers only, never who
 * those incidents were about.
 */
public record AgentRequest(IncidentPart incident, Baseline baseline, List<IndicatorService.Recent> recentIndicators) {

    public record IncidentPart(Long id, String kind, String subjectIdentity, JsonNode payload) {
    }
}
