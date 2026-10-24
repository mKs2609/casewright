package com.securityanalyst.gateway.investigation;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Keeps each incident's indicators and answers "what did recent incidents contain?" for
 * the next investigation (step 10b). The agent itself keeps nothing (ADR-3): this history
 * lives in the gateway, and only values and incident numbers are sent, never who an
 * incident was about.
 */
@Service
public class IndicatorService {

    /** One indicator and the recent incidents (newest first, at most 20) it appeared in. */
    public record Recent(String type, String value, List<Long> incidentIds) {
    }

    static final int MAX_INCIDENTS_PER_INDICATOR = 20;

    private final JdbcTemplate jdbc;
    private final Duration window;
    private final int limit;

    public IndicatorService(JdbcTemplate jdbc,
            @Value("${agent.related-incident-window}") Duration window,
            @Value("${agent.max-recent-indicators}") int limit) {
        this.jdbc = jdbc;
        this.window = window;
        this.limit = limit;
    }

    /** Saves the indicators reported for an incident (already checked by the caller). */
    @Transactional
    public void record(Long incidentId, List<AgentEvent.Indicator> indicators) {
        jdbc.batchUpdate("INSERT INTO incident_indicators (incident_id, type, value) VALUES (?, ?, ?) "
                + "ON CONFLICT DO NOTHING",
                indicators.stream().map(i -> new Object[] { incidentId, i.type(), i.value() }).toList());
    }

    /**
     * Indicators of other incidents created within the window, the most recently seen first,
     * at most {@code agent.max-recent-indicators} of them.
     */
    @Transactional(readOnly = true)
    public List<Recent> recentExcept(Long incidentId) {
        Instant since = Instant.now().minus(window);
        return jdbc.query("""
                SELECT ii.type, ii.value, array_agg(ii.incident_id ORDER BY ii.incident_id DESC) AS ids
                FROM incident_indicators ii JOIN incidents i ON i.id = ii.incident_id
                WHERE i.created_at >= ? AND ii.incident_id <> ?
                GROUP BY ii.type, ii.value
                ORDER BY max(i.created_at) DESC, ii.type, ii.value
                LIMIT ?""",
                (rs, row) -> {
                    Long[] ids = (Long[]) rs.getArray("ids").getArray();
                    return new Recent(rs.getString("type"), rs.getString("value"),
                            Arrays.asList(ids).subList(0, Math.min(ids.length, MAX_INCIDENTS_PER_INDICATOR)));
                },
                Timestamp.from(since), incidentId, limit);
    }
}
