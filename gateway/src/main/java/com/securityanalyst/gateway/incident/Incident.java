package com.securityanalyst.gateway.incident;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.identity.MonitoredIdentity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** One row of the incidents table: a suspicious event waiting to be (or being) investigated. */
@Entity
@Table(name = "incidents")
public class Incident {

    static final String STATUS_QUEUED = "queued";
    static final String SOURCE_API = "api";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 20)
    private String kind;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "subject_identity", nullable = false)
    private MonitoredIdentity subject;

    /** The validated request as JSON text; stored in a JSONB column, so PostgreSQL checks it is valid JSON. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false)
    private String payload;

    @Column(nullable = false, length = 20)
    private String status;

    @Column(nullable = false, length = 40)
    private String source;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by", nullable = false)
    private User createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** Required by JPA. */
    protected Incident() {
    }

    Incident(String kind, MonitoredIdentity subject, String payload, String source, User createdBy) {
        this.kind = kind;
        this.subject = subject;
        this.payload = payload;
        this.status = STATUS_QUEUED;
        this.source = source;
        this.createdBy = createdBy;
    }

    public Long getId() {
        return id;
    }

    public String getKind() {
        return kind;
    }

    public MonitoredIdentity getSubject() {
        return subject;
    }

    public String getPayload() {
        return payload;
    }

    public String getStatus() {
        return status;
    }

    public String getSource() {
        return source;
    }

    public User getCreatedBy() {
        return createdBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
