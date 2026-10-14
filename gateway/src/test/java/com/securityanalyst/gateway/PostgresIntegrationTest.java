package com.securityanalyst.gateway;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;

/**
 * Base class for tests that start the whole application. Starts one real,
 * throwaway PostgreSQL for the whole test run and points Spring at it, so tests
 * never touch the development database and need no password or setup.
 * It also supplies a random token-signing key, so tests never use the real one.
 */
public abstract class PostgresIntegrationTest {

    private static final EmbeddedPostgres POSTGRES = start();

    /** A fresh random signing key for each test run. */
    protected static final String TEST_JWT_KEY = randomKey();

    private static EmbeddedPostgres start() {
        try {
            return EmbeddedPostgres.builder().start();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not start embedded PostgreSQL for tests", e);
        }
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    @DynamicPropertySource
    static void pointSpringAtTestResources(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "");
        registry.add("security.jwt.signing-key", () -> TEST_JWT_KEY);
    }
}
