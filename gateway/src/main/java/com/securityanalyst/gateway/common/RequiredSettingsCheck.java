package com.securityanalyst.gateway.common;

import java.util.List;

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

    static final List<String> REQUIRED = List.of("DB_URL", "DB_USER", "DB_PASSWORD", "JWT_SIGNING_KEY");

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        List<String> missing = missingSettings(event.getEnvironment());
        if (!missing.isEmpty()) {
            throw new IllegalStateException("Missing required settings: " + String.join(", ", missing)
                    + ". Run scripts\\setup-db.ps1 (database settings) and scripts\\setup-secrets.ps1"
                    + " (application secrets) to create the .env file, or set these as environment variables.");
        }
    }

    static List<String> missingSettings(Environment environment) {
        return REQUIRED.stream()
                .filter(name -> {
                    String value = environment.getProperty(name);
                    return value == null || value.isBlank();
                })
                .toList();
    }
}
