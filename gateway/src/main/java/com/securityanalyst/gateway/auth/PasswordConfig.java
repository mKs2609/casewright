package com.securityanalyst.gateway.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Creates the one PasswordEncoder the whole application uses. */
@Configuration
public class PasswordConfig {

    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    /**
     * Argon2id: slow and memory-hungry on purpose, so guessing passwords in bulk
     * is impractical. Each hash carries its own random salt and these settings,
     * so the settings can be raised later without breaking existing accounts.
     */
    @Bean
    PasswordEncoder passwordEncoder(
            @Value("${security.password.argon2.memory-kib}") int memoryKib,
            @Value("${security.password.argon2.iterations}") int iterations,
            @Value("${security.password.argon2.parallelism}") int parallelism) {
        return new Argon2PasswordEncoder(SALT_BYTES, HASH_BYTES, parallelism, memoryKib, iterations);
    }
}
