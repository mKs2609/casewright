package com.securityanalyst.gateway.identity;

import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tools.jackson.databind.json.JsonMapper;

/** Monitored identities and their baselines. Baselines are encrypted on the way in and decrypted on the way out. */
@Service
public class MonitoredIdentityService {

    private final MonitoredIdentityRepository identities;
    private final BaselineCipher cipher;
    private final JsonMapper json;

    public MonitoredIdentityService(MonitoredIdentityRepository identities, BaselineCipher cipher, JsonMapper json) {
        this.identities = identities;
        this.cipher = cipher;
        this.json = json;
    }

    @Transactional
    public MonitoredIdentity create(String identity, String displayName, Baseline baseline) {
        byte[] encrypted = cipher.encrypt(json.writeValueAsBytes(baseline), identity);
        return identities.save(new MonitoredIdentity(identity, displayName, encrypted));
    }

    @Transactional(readOnly = true)
    public boolean exists(String identity) {
        return identities.existsById(identity);
    }

    @Transactional(readOnly = true)
    public Optional<MonitoredIdentity> find(String identity) {
        return identities.findById(identity);
    }

    @Transactional(readOnly = true)
    public Optional<Baseline> baselineOf(String identity) {
        return identities.findById(identity)
                .map(found -> json.readValue(cipher.decrypt(found.getEncryptedBaseline(), identity), Baseline.class));
    }
}
