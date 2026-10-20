package com.securityanalyst.gateway.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;

/** The demo employees, and their baselines as the database actually stores them. */
@SpringBootTest
@Transactional
class MonitoredIdentitiesTest extends PostgresIntegrationTest {

    @Autowired
    private MonitoredIdentityService identities;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void theThreeDemoEmployeesAreAddedAtStartup() {
        List<String> stored = jdbc.queryForList("SELECT identity FROM monitored_identities ORDER BY identity", String.class);

        assertThat(stored).contains("arjun.mehta", "priya.sharma", "sara.khan");
    }

    @Test
    void aBaselineIsUnreadableInTheDatabaseButReadableThroughTheService() {
        byte[] raw = jdbc.queryForObject("SELECT baseline FROM monitored_identities WHERE identity = 'priya.sharma'",
                byte[].class);
        String asText = new String(raw, StandardCharsets.ISO_8859_1);
        assertThat(asText).doesNotContain("usualCountries").doesNotContain("Bengaluru").doesNotContain("example.com");

        Baseline baseline = identities.baselineOf("priya.sharma").orElseThrow();
        assertThat(baseline.usualCountries()).containsExactly("IN");
        assertThat(baseline.homeCity()).isEqualTo("Bengaluru");
        assertThat(baseline.knownContacts()).contains("it-support@example.com");
    }

    @Test
    void copyingOnePersonsBaselineOntoAnotherIsDetected() {
        // Someone with write access to the table copies Sara's (wider) baseline onto Priya's row.
        jdbc.update("UPDATE monitored_identities SET baseline = "
                + "(SELECT baseline FROM monitored_identities WHERE identity = 'sara.khan') WHERE identity = 'priya.sharma'");

        assertThatThrownBy(() -> identities.baselineOf("priya.sharma"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("wrong key, wrong row, or the data was altered");
    }

    @Test
    void anUnknownIdentityHasNoBaseline() {
        assertThat(identities.baselineOf("nobody.here")).isEmpty();
    }
}
