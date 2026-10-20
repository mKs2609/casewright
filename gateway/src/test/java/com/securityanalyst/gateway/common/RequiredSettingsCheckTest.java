package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

/** Plain unit test: no Spring context, no database. */
class RequiredSettingsCheckTest {

    @Test
    void nothingMissingWhenAllSettingsPresent() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("DB_URL", "jdbc:postgresql://localhost:5432/secanalyst")
                .withProperty("DB_USER", "secanalyst_app")
                .withProperty("DB_PASSWORD", "x")
                .withProperty("JWT_SIGNING_KEY", "x")
                .withProperty("SSL_KEYSTORE_PASSWORD", "x")
                .withProperty("BASELINE_ENCRYPTION_KEY", "x");

        assertThat(RequiredSettingsCheck.missingSettings(env)).isEmpty();
    }

    @Test
    void reportsEverySettingThatIsAbsentOrBlank() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("DB_URL", "jdbc:postgresql://localhost:5432/secanalyst")
                .withProperty("DB_PASSWORD", "   ");

        assertThat(RequiredSettingsCheck.missingSettings(env)).containsExactly("DB_USER", "DB_PASSWORD", "JWT_SIGNING_KEY", "SSL_KEYSTORE_PASSWORD",
                "BASELINE_ENCRYPTION_KEY");
    }

    @Test
    void reportsAMissingCertificateFile(@TempDir Path dir) throws IOException {
        Path keyStore = dir.resolve("gateway-dev.p12");
        MockEnvironment env = new MockEnvironment().withProperty("server.ssl.key-store", "file:" + keyStore);

        assertThat(RequiredSettingsCheck.missingKeyStore(env)).contains(keyStore.toAbsolutePath().normalize());

        Files.writeString(keyStore, "not checked here, only that it exists");
        assertThat(RequiredSettingsCheck.missingKeyStore(env)).isEmpty();
    }
}
