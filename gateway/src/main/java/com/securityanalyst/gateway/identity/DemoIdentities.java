package com.securityanalyst.gateway.identity;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Adds three fictional employees at startup if they are missing, so there is someone for
 * incidents to be about. Switched by demo.seed-identities (on for local development).
 *
 * This lives in code rather than in a database migration because the baselines must be
 * encrypted with the key from .env, which a migration never sees.
 * All names, addresses and numbers are made up: example.com is reserved for examples and
 * 555-01xx numbers are reserved for fiction.
 */
@Component
@ConditionalOnProperty(name = "demo.seed-identities", havingValue = "true")
public class DemoIdentities implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoIdentities.class);

    record Person(String identity, String displayName, Baseline baseline) {
    }

    static final List<Person> PEOPLE = List.of(
            new Person("priya.sharma", "Priya Sharma", new Baseline(
                    List.of("IN"), 3, 15, List.of("Windows NT 10.0"),
                    List.of("it-support@example.com", "hr@example.com", "ceo@example.com"),
                    List.of("+15555550100"), "Bengaluru")),
            new Person("arjun.mehta", "Arjun Mehta", new Baseline(
                    List.of("IN"), 4, 17, List.of("Macintosh"),
                    List.of("it-support@example.com", "hr@example.com"),
                    List.of("+15555550100"), "Mumbai")),
            new Person("sara.khan", "Sara Khan", new Baseline(
                    List.of("IN", "AE"), 3, 16, List.of("Android", "Windows NT 10.0"),
                    List.of("it-support@example.com", "sales-ops@example.com"),
                    List.of("+15555550100", "+15555550199"), "Delhi")));

    private final MonitoredIdentityService identities;

    public DemoIdentities(MonitoredIdentityService identities) {
        this.identities = identities;
    }

    @Override
    public void run(ApplicationArguments args) {
        int added = 0;
        for (Person person : PEOPLE) {
            if (!identities.exists(person.identity())) {
                identities.create(person.identity(), person.displayName(), person.baseline());
                added++;
            }
        }
        if (added > 0) {
            log.info("Added {} demo monitored identities", added);
        }
    }
}
