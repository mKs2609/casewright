package com.securityanalyst.gateway.investigation;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import com.securityanalyst.gateway.incident.IncidentService;

/**
 * Investigations run in memory, so any still unfinished when the gateway starts were cut off
 * when it last stopped (ADR-39). Marked as error, instead of showing "investigating" forever.
 */
@Component
public class StuckInvestigations {

    private static final Logger log = LoggerFactory.getLogger(StuckInvestigations.class);

    private final JdbcTemplate jdbc;
    private final IncidentService incidents;
    private final boolean enabled;

    public StuckInvestigations(JdbcTemplate jdbc, IncidentService incidents,
            @Value("${agent.recover-stuck-on-startup}") boolean enabled) {
        this.jdbc = jdbc;
        this.incidents = incidents;
        this.enabled = enabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        if (enabled) {
            markAsError();
        }
    }

    void markAsError() {
        List<Long> stuck = jdbc.queryForList("SELECT id FROM incidents WHERE status IN ('queued', 'investigating')", Long.class);
        for (Long id : stuck) {
            log.warn("Incident {}: its investigation was cut off when the gateway stopped", id);
            incidents.updateStatus(id, "error");
        }
    }
}
