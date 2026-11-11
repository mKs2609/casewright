package com.securityanalyst.gateway.auth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.audit.AuditLog;

/**
 * The shared account behind the public demo's "Try the demo" button (step 19b, ADR-55). Exists only
 * when demo.public-login.enabled is on (the public server); a development machine has none.
 *
 * It is an analyst, so visitors can fire the demo scenarios, run the red-team probe and approve
 * or reject the actions that follow (which are only ever simulated, ADR-13). Its password is a
 * fresh random value at every start that nobody ever sees: the only way in is the button, so there
 * is no password to publish, guess or change.
 */
@Component
@ConditionalOnProperty(name = "demo.public-login.enabled", havingValue = "true")
public class DemoAccount implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoAccount.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuditLog audit;
    private final String username;

    public DemoAccount(UserRepository users, PasswordEncoder passwordEncoder, AuditLog audit,
            @Value("${demo.public-login.username}") String username) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
        this.username = username;
    }

    /** At startup: the account exists, is an analyst, and has a new password nobody knows. */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        String unknowable = passwordEncoder.encode(randomPassword());
        User account = users.findByUsername(username).orElse(null);
        if (account == null) {
            users.save(new User(username, unknowable, Role.ANALYST));
            audit.record(username, "auth.demo_account_created", null, Map.of());
            log.info("Created the public demo account");
            return;
        }
        account.setPasswordHash(unknowable);
        if (account.getRole() != Role.ANALYST) {
            // Not more (an admin could manage users), not less (it could not use the demo).
            audit.record(username, "auth.demo_account_role_reset", null, Map.of("from", account.getRole().name()));
            account.setRole(Role.ANALYST);
        }
    }

    public String username() {
        return username;
    }

    private static String randomPassword() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
