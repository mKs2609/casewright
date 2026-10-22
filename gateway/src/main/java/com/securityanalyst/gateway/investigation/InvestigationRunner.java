package com.securityanalyst.gateway.investigation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import com.securityanalyst.gateway.evidence.EvidenceService;
import com.securityanalyst.gateway.identity.MonitoredIdentityService;
import com.securityanalyst.gateway.incident.IncidentService;
import com.securityanalyst.gateway.incident.IncidentSubmitted;

import tools.jackson.databind.json.JsonMapper;

/**
 * Runs the investigation of each new incident in the background, so the analyst gets
 * their "202 Accepted" at once instead of waiting for the agent.
 *
 * Status: queued -> investigating -> (the agent's result, e.g. needs_review), or error.
 * Each tool call the agent reports is saved as evidence the moment it arrives.
 */
@Component
public class InvestigationRunner {

    private static final Logger log = LoggerFactory.getLogger(InvestigationRunner.class);

    private final IncidentService incidents;
    private final MonitoredIdentityService identities;
    private final AgentClient agent;
    private final EvidenceService evidence;
    private final JsonMapper json;

    public InvestigationRunner(IncidentService incidents, MonitoredIdentityService identities, AgentClient agent,
            EvidenceService evidence, JsonMapper json) {
        this.incidents = incidents;
        this.identities = identities;
        this.agent = agent;
        this.evidence = evidence;
        this.json = json;
    }

    /**
     * AFTER_COMMIT: only once the incident is safely in the database (never for one that
     * was rolled back). @Async: on a background thread, not the request's.
     */
    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onSubmitted(IncidentSubmitted submitted) {
        run(submitted.incidentId());
    }

    void run(Long incidentId) {
        incidents.updateStatus(incidentId, "investigating");
        try {
            EvidenceChain chain = new EvidenceChain(incidentId);
            AgentEvent.Complete result = agent.investigate(requestFor(incidentId), chain::accept);
            incidents.updateStatus(incidentId, result.result());
            log.info("Incident {}: investigation finished ({}, engine {})", incidentId, result.result(), result.engine());
        } catch (RuntimeException e) {
            // Unexpected problems are logged in full; agent problems by their message only.
            if (e instanceof AgentException) {
                log.warn("Incident {}: investigation failed: {}", incidentId, e.getMessage());
            } else {
                log.error("Incident {}: investigation failed unexpectedly", incidentId, e);
            }
            incidents.updateStatus(incidentId, "error");
        }
    }

    /**
     * Records the agent's events for one investigation, checking the numbering as it goes:
     * evidence must arrive as E1, E2, E3, ... and refusals as R1, R2, ..., with no gaps or
     * repeats (ADR-5: a confused or compromised agent cannot rewrite or skip evidence).
     */
    private final class EvidenceChain {

        private final Long incidentId;
        private int accepted;
        private int rejected;

        EvidenceChain(Long incidentId) {
            this.incidentId = incidentId;
        }

        void accept(AgentEvent event) {
            switch (event) {
                case AgentEvent.Thought thought -> log.info("Incident {}: agent: {}", incidentId, thought.text());
                case AgentEvent.Step step -> {
                    expect(step.label(), "E" + (accepted + 1));
                    if (!step.result().isObject()) {
                        throw new AgentException("The agent sent " + step.label() + " without a result object");
                    }
                    evidence.recordAccepted(incidentId, step.label(), step.tool(), step.args(), step.summary(),
                            step.result(), step.signals());
                    accepted++;
                    log.info("Incident {}: {} {}", incidentId, step.label(), step.summary());
                }
                case AgentEvent.Guardrail refused -> {
                    expect(refused.label(), "R" + (rejected + 1));
                    evidence.recordRejected(incidentId, refused.label(), refused.tool(), refused.args(), refused.reason());
                    rejected++;
                    log.warn("Incident {}: {} refused a {} call: {}", incidentId, refused.label(), refused.tool(),
                            refused.reason());
                }
                case AgentEvent.Complete complete -> {
                    // Handled by the caller once the answer has been read to the end.
                }
            }
        }

        private void expect(String label, String expected) {
            if (!label.equals(expected)) {
                throw new AgentException("The agent sent evidence " + label + " where " + expected + " was expected");
            }
        }
    }

    /** Packs up the incident and its subject's decrypted baseline (ADR-3: the agent gets everything it needs). */
    AgentRequest requestFor(Long incidentId) {
        IncidentService.InvestigationInput incident = incidents.investigationInput(incidentId);
        var baseline = identities.baselineOf(incident.subjectIdentity())
                .orElseThrow(() -> new IllegalStateException("No baseline for " + incident.subjectIdentity()));
        return new AgentRequest(new AgentRequest.IncidentPart(incident.id(), incident.kind(), incident.subjectIdentity(),
                json.readTree(incident.payloadJson())), baseline);
    }
}
