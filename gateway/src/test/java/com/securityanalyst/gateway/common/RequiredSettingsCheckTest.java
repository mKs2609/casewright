package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** Plain unit test: no Spring context, no database. */
class RequiredSettingsCheckTest {

    @Test
    void nothingMissingWhenAllSettingsPresent() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("DB_URL", "jdbc:postgresql://localhost:5432/secanalyst")
                .withProperty("DB_USER", "secanalyst_app")
                .withProperty("DB_PASSWORD", "x")
                .withProperty("JWT_SIGNING_KEY", "x");

        assertThat(RequiredSettingsCheck.missingSettings(env)).isEmpty();
    }

    @Test
    void reportsEverySettingThatIsAbsentOrBlank() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("DB_URL", "jdbc:postgresql://localhost:5432/secanalyst")
                .withProperty("DB_PASSWORD", "   ");

        assertThat(RequiredSettingsCheck.missingSettings(env)).containsExactly("DB_USER", "DB_PASSWORD", "JWT_SIGNING_KEY");
    }
}
