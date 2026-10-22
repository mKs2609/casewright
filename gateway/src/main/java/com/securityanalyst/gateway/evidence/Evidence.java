package com.securityanalyst.gateway.evidence;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One row of the evidence table: one tool call made while investigating an incident.
 * Accepted calls are E1, E2, ...; refused ones are R1, R2, ... with the reason.
 * Rows are only ever added, never changed.
 */
@Entity
@Table(name = "evidence")
public class Evidence {

    static final String OK = "ok";
    static final String REJECTED = "rejected";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "incident_id", nullable = false, updatable = false)
    private Long incidentId;

    @Column(nullable = false, updatable = false, length = 4)
    private String label;

    @Column(nullable = false, updatable = false, length = 40)
    private String tool;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, updatable = false)
    private String args;

    @Column(nullable = false, updatable = false, length = 10)
    private String status;

    @Column(updatable = false, length = 500)
    private String summary;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(updatable = false)
    private String result;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, updatable = false)
    private String signals;

    @Column(updatable = false, length = 500)
    private String reason;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** Required by JPA. */
    protected Evidence() {
    }

    private Evidence(Long incidentId, String label, String tool, String args, String status, String summary,
            String result, String signals, String reason) {
        this.incidentId = incidentId;
        this.label = label;
        this.tool = tool;
        this.args = args;
        this.status = status;
        this.summary = summary;
        this.result = result;
        this.signals = signals;
        this.reason = reason;
    }

    static Evidence accepted(Long incidentId, String label, String tool, String args, String summary, String result,
            String signals) {
        return new Evidence(incidentId, label, tool, args, OK, summary, result, signals, null);
    }

    static Evidence rejected(Long incidentId, String label, String tool, String args, String reason) {
        return new Evidence(incidentId, label, tool, args, REJECTED, null, null, "[]", reason);
    }

    public Long getIncidentId() {
        return incidentId;
    }

    public String getLabel() {
        return label;
    }

    public String getTool() {
        return tool;
    }

    public String getArgs() {
        return args;
    }

    public String getStatus() {
        return status;
    }

    public String getSummary() {
        return summary;
    }

    public String getResult() {
        return result;
    }

    public String getSignals() {
        return signals;
    }

    public String getReason() {
        return reason;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
