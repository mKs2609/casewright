package com.securityanalyst.gateway.db;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;

/**
 * Checks that Flyway ran migration V1 and that the rules written into the
 * table (unique username, allowed roles, username format) are really enforced
 * by the database itself.
 * {@code @Transactional} rolls every test back, so tests don't affect each other.
 */
@SpringBootTest
@Transactional
class AppUsersMigrationTest extends PostgresIntegrationTest {

    private static final String INSERT = "INSERT INTO app_users (username, password_hash) VALUES (?, ?)";

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void flywayAppliedTheFirstMigration() {
        Integer applied = jdbc.queryForObject(
                "SELECT count(*) FROM flyway_schema_history WHERE version = '1' AND success", Integer.class);
        assertThat(applied).isEqualTo(1);
    }

    @Test
    void newUserGetsViewerRoleAndCreationTimeByDefault() {
        jdbc.update(INSERT, "asha.rao", "hash-placeholder");

        Map<String, Object> row = jdbc.queryForMap("SELECT * FROM app_users WHERE username = ?", "asha.rao");
        assertThat(row.get("role")).isEqualTo("VIEWER");
        assertThat(row.get("created_at")).isNotNull();
        assertThat(row.get("id")).isNotNull();
    }

    @Test
    void duplicateUsernameIsRejected() {
        jdbc.update(INSERT, "asha.rao", "hash-1");

        assertThatThrownBy(() -> jdbc.update(INSERT, "asha.rao", "hash-2"))
                .isInstanceOf(DuplicateKeyException.class);
    }

    @Test
    void unknownRoleIsRejected() {
        assertThatThrownBy(() -> jdbc.update(
                "INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?)",
                "asha.rao", "hash", "SUPERUSER"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // PostgreSQL aborts a transaction after the first error, so this test runs each
    // insert on its own. Nothing is saved, because every insert is rejected.
    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void badlyFormedUsernamesAreRejected() {
        for (String bad : new String[] { "ab", "Asha", "asha rao", "asha'; DROP TABLE app_users;--" }) {
            assertThatThrownBy(() -> jdbc.update(INSERT, bad, "hash"))
                    .as("username '%s' should be rejected", bad)
                    .isInstanceOf(DataIntegrityViolationException.class);
        }
    }

    @Test
    void passwordHashIsRequired() {
        assertThatThrownBy(() -> jdbc.update(INSERT, "asha.rao", null))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
