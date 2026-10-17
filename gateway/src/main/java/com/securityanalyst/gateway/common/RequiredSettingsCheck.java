package com.securityanalyst.gateway.common;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.Environment;

/**
 * Stops the application at startup, with a clear message, if a required
 * setting is missing. Secrets have no defaults on purpose, so a forgotten
 * setting must fail loudly instead of running in an insecure state.
 * Runs after Spring has loaded the .env file and the environment variables.
 */
public class RequiredSettingsCheck implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    static final List<String> REQUIRED =
            List.of("DB_URL", "DB_USER", "DB_PASSWORD", "JWT_SIGNING_KEY", "SSL_KEYSTORE_PASSWORD");

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        Environment environment = event.getEnvironment();
        List<String> missing = missingSettings(environment);
        if (!missing.isEmpty()) {
            throw new IllegalStateException("Missing required settings: " + String.join(", ", missing)
                    + ". Run scripts\\setup-db.ps1 (database settings) and scripts\\setup-secrets.ps1"
                    + " (application secrets) to create the .env file, or set these as environment variables.");
        }
        missingKeyStore(environment).ifPresent(path -> {
            throw new IllegalStateException("The HTTPS certificate was not found at " + path
                    + ". Run scripts\\setup-https.ps1 to create it.");
        });
    }

    static List<String> missingSettings(Environment environment) {
        return REQUIRED.stream()
                .filter(name -> {
                    String value = environment.getProperty(name);
                    return value == null || value.isBlank();
                })
                .toList();
    }

    /** The keystore file, if the settings point at a file on disk that does not exist. */
    static Optional<Path> missingKeyStore(Environment environment) {
        String location = environment.getProperty("server.ssl.key-store", "");
        if (!location.startsWith("file:")) {
            return Optional.empty();
        }
        Path path = Path.of(location.substring("file:".length())).toAbsolutePath().normalize();
        return Files.isRegularFile(path) ? Optional.empty() : Optional.of(path);
    }
}
