package com.securityanalyst.gateway.identity;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One row of monitored_identities: an employee the product protects. Not someone who
 * logs in (that is app_users). The baseline is held encrypted, exactly as stored;
 * MonitoredIdentityService is the only place that encrypts or decrypts it.
 */
@Entity
@Table(name = "monitored_identities")
public class MonitoredIdentity {

    @Id
    @Column(length = 64)
    private String identity;

    @Column(name = "display_name", nullable = false, length = 100)
    private String displayName;

    @Column(name = "baseline", nullable = false)
    private byte[] encryptedBaseline;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** Required by JPA. */
    protected MonitoredIdentity() {
    }

    MonitoredIdentity(String identity, String displayName, byte[] encryptedBaseline) {
        this.identity = identity;
        this.displayName = displayName;
        this.encryptedBaseline = encryptedBaseline;
    }

    public String getIdentity() {
        return identity;
    }

    public String getDisplayName() {
        return displayName;
    }

    byte[] getEncryptedBaseline() {
        return encryptedBaseline;
    }
}
