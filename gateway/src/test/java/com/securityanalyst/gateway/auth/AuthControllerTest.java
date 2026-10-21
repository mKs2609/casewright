package com.securityanalyst.gateway.auth;

import static com.securityanalyst.gateway.NoEcho.doesNotEcho;
import static com.securityanalyst.gateway.NoEcho.withoutTraceId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import com.securityanalyst.gateway.PostgresIntegrationTest;

/**
 * Signup and login, end to end: real HTTP handling, real validation, real
 * Argon2 hashing, real (throwaway) database. Each test is rolled back.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthControllerTest extends PostgresIntegrationTest {

    private static final String GOOD_PASSWORD = "correct horse battery staple";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private ResultActions postJson(String path, String json) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private static String credentials(String username, String password) {
        return "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }

    // ------------------------------------------------------------------ signup

    @Test
    void signupCreatesAViewerAndNeverReturnsThePassword() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("asha.rao"))
                .andExpect(jsonPath("$.role").value("VIEWER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(content().string(not(containsString(GOOD_PASSWORD))));
    }

    @Test
    void passwordIsStoredAsAnArgon2HashNotAsText() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());

        String stored = users.findByUsername("asha.rao").orElseThrow().getPasswordHash();
        assertThat(stored).startsWith("$argon2id$").doesNotContain(GOOD_PASSWORD);
        assertThat(passwordEncoder.matches(GOOD_PASSWORD, stored)).isTrue();
        assertThat(passwordEncoder.matches("some other password", stored)).isFalse();
    }

    @Test
    void samePasswordGivesDifferentHashesBecauseOfTheSalt() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());
        postJson("/api/auth/signup", credentials("ravi.k", GOOD_PASSWORD)).andExpect(status().isCreated());

        assertThat(users.findByUsername("asha.rao").orElseThrow().getPasswordHash())
                .isNotEqualTo(users.findByUsername("ravi.k").orElseThrow().getPasswordHash());
    }

    @Test
    void duplicateUsernameIsRejected() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());

        postJson("/api/auth/signup", credentials("asha.rao", "a different long password"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Username is already taken"));
    }

    @Test
    void nobodyCanGiveThemselvesARoleAtSignup() throws Exception {
        postJson("/api/auth/signup",
                "{\"username\":\"mallory\",\"password\":\"" + GOOD_PASSWORD + "\",\"role\":\"ADMIN\"}")
                .andExpect(status().isBadRequest());

        assertThat(users.existsByUsername("mallory")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = { "ab", "Asha", "asha rao", "asha<script>", "a-name-that-is-far-too-long-to-be-allowed" })
    void badlyFormedUsernamesAreRejectedWithoutEchoingThem(String badUsername) throws Exception {
        postJson("/api/auth/signup", credentials(badUsername, GOOD_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation failed"))
                .andExpect(jsonPath("$.fields.username").exists())
                .andExpect(doesNotEcho(badUsername));
    }

    @Test
    void shortPasswordIsRejectedWithoutEchoingIt() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", "short-pw"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.password").value("must be 12-128 characters"))
                .andExpect(doesNotEcho("short-pw"));
    }

    @Test
    void hugePasswordIsRejectedBeforeAnyHashingHappens() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", "x".repeat(129)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.password").exists());
    }

    @Test
    void passwordContainingTheUsernameIsRejected() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", "Asha.Rao-is-my-password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Password must not contain the username"));
    }

    @Test
    void missingFieldsAndBrokenJsonAreRejected() throws Exception {
        postJson("/api/auth/signup", "{\"username\":\"asha.rao\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.password").value("is required"));

        postJson("/api/auth/signup", "{ this is not json").andExpect(status().isBadRequest());
        postJson("/api/auth/signup", "").andExpect(status().isBadRequest());
    }

    // ------------------------------------------------------------------ login

    @Test
    void loginSucceedsWithTheRightPassword() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());

        postJson("/api/auth/login", credentials("asha.rao", GOOD_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("asha.rao"))
                .andExpect(jsonPath("$.role").value("VIEWER"));
    }

    @Test
    void wrongPasswordAndUnknownUserGetTheExactSameAnswer() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());

        String wrongPassword = postJson("/api/auth/login", credentials("asha.rao", "not the right password"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String unknownUser = postJson("/api/auth/login", credentials("nobody.here", GOOD_PASSWORD))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        // Every response carries its own random trace ID, so blank that out; everything
        // else (message, field names, order) must be byte-for-byte identical.
        assertThat(withoutTraceId(wrongPassword)).isEqualTo(withoutTraceId(unknownUser))
                .isEqualTo("{\"error\":\"Invalid username or password\",\"traceId\":\"*\"}");
    }

    @Test
    void sqlInjectionInTheLoginUsernameDoesNothing() throws Exception {
        postJson("/api/auth/signup", credentials("asha.rao", GOOD_PASSWORD)).andExpect(status().isCreated());

        postJson("/api/auth/login", credentials("asha.rao' OR '1'='1", "anything at all"))
                .andExpect(status().isUnauthorized());
        assertThat(users.count()).isEqualTo(1);
    }

    @Test
    void loginRejectsBlankAndOversizedInput() throws Exception {
        postJson("/api/auth/login", credentials("", "")).andExpect(status().isBadRequest());
        postJson("/api/auth/login", credentials("asha.rao", "x".repeat(129))).andExpect(status().isBadRequest());
    }
}
