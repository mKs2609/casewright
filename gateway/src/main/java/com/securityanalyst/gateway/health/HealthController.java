package com.securityanalyst.gateway.health;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Answers "is the gateway alive, and can it reach its database?". Used by us
 * while developing, and later by the dashboard, CI and Docker health checks.
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    private final JdbcTemplate jdbc;
    private final Instant startedAt = Instant.now();

    public HealthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/health")
    public ResponseEntity<HealthResponse> health() {
        boolean databaseUp = databaseIsUp();
        String status = databaseUp ? "UP" : "DOWN";
        HttpStatus httpStatus = databaseUp ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE;
        return ResponseEntity.status(httpStatus)
                .body(new HealthResponse(status, "gateway", status, startedAt));
    }

    private boolean databaseIsUp() {
        try {
            jdbc.queryForObject("SELECT 1", Integer.class);
            return true;
        } catch (DataAccessException e) {
            // The reason goes to the server log only; the caller just sees "DOWN".
            log.warn("Database health check failed: {}", e.getMessage());
            return false;
        }
    }

    /** Spring turns this record into JSON automatically. */
    public record HealthResponse(String status, String service, String database, Instant startedAt) {
    }
}
