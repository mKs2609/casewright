package com.securityanalyst.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.securityanalyst.gateway.PostgresIntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * Sessions (cookies, access tokens, refresh-token rotation) and roles.
 *
 * Unlike the other test classes this one is NOT wrapped in a rolled-back
 * transaction: every request commits for real, exactly as in production, which
 * matters for checking that a revocation is truly saved. The tables are emptied
 * before each test instead.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessionAndRolesTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private UserRepository users;
    @Autowired
    private RefreshTokenRepository refreshTokens;
    @Autowired
    private PasswordEncoder passwordEncoder;

    // Before AND after: this class commits its users, and the test database is shared by every
    // class, so leftovers would break whichever class runs next (the order differs between machines).
    @BeforeEach
    @AfterEach
    void emptyTables() {
        refreshTokens.deleteAll();
        users.deleteAll();
    }

    // ------------------------------------------------------------------ helpers

    private User createUser(String username, Role role) {
        return users.save(new User(username, passwordEncoder.encode(PASSWORD), role));
    }

    private MockHttpServletResponse login(String username) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse();
    }

    private Cookie accessCookie(String username) throws Exception {
        return login(username).getCookie(AuthCookies.ACCESS_TOKEN);
    }

    private MockHttpServletResponse refreshWith(Cookie refreshCookie) throws Exception {
        return mvc.perform(post("/api/auth/refresh").cookie(refreshCookie)).andReturn().getResponse();
    }

    private static MockHttpServletRequestBuilder changeRole(Long userId, String role) {
        return put("/api/admin/users/" + userId + "/role").contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"" + role + "\"}");
    }

    /** Builds a token the way an attacker (or a test) would, with any key and any expiry. */
    private static String handMadeToken(String base64Key, User user, Role claimedRole, Instant expiresAt) {
        var key = new SecretKeySpec(Base64.getDecoder().decode(base64Key), "HmacSHA256");
        var claims = JwtClaimsSet.builder()
                .subject(String.valueOf(user.getId()))
                .claim("username", user.getUsername())
                .claim("role", claimedRole.name())
                .issuedAt(expiresAt.minusSeconds(900))
                .expiresAt(expiresAt)
                .build();
        return new NimbusJwtEncoder(new ImmutableSecret<>(key))
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }

    // ------------------------------------------------------------------ cookies

    @Test
    void loginSetsTwoLockedDownCookiesAndPutsNoTokenInTheBody() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        MockHttpServletResponse response = login("asha.rao");

        for (String name : new String[] { AuthCookies.ACCESS_TOKEN, AuthCookies.REFRESH_TOKEN }) {
            Cookie cookie = response.getCookie(name);
            assertThat(cookie).as(name).isNotNull();
            assertThat(cookie.isHttpOnly()).as(name + " HttpOnly").isTrue();
            assertThat(cookie.getSecure()).as(name + " Secure").isTrue();
            assertThat(cookie.getAttribute("SameSite")).as(name + " SameSite").isEqualTo("Strict");
            assertThat(response.getContentAsString()).doesNotContain(cookie.getValue());
        }
        assertThat(response.getCookie(AuthCookies.ACCESS_TOKEN).getPath()).isEqualTo("/");
        assertThat(response.getCookie(AuthCookies.REFRESH_TOKEN).getPath()).isEqualTo("/api/auth");
    }

    @Test
    void refreshTokenIsStoredOnlyAsAFingerprint() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        String rawToken = login("asha.rao").getCookie(AuthCookies.REFRESH_TOKEN).getValue();

        assertThat(refreshTokens.findAll()).singleElement().satisfies(stored -> {
            assertThat(stored.getTokenHash()).isNotEqualTo(rawToken).hasSize(64);
            assertThat(stored.getTokenHash()).isEqualTo(SessionService.fingerprint(rawToken));
        });
    }

    // ------------------------------------------------------------------ access tokens

    @Test
    void protectedUrlsNeedALogin() throws Exception {
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Authentication required"));
        mvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
    }

    @Test
    void aValidAccessTokenIdentifiesTheCaller() throws Exception {
        createUser("asha.rao", Role.ANALYST);

        mvc.perform(get("/api/me").cookie(accessCookie("asha.rao")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("asha.rao"))
                .andExpect(jsonPath("$.role").value("ANALYST"));
    }

    @Test
    void anAlteredTokenIsRejected() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        String token = accessCookie("asha.rao").getValue();
        // Flip one character in the middle part (the claims). The signature no longer matches.
        int i = token.indexOf('.') + 5;
        String altered = token.substring(0, i) + (token.charAt(i) == 'A' ? 'B' : 'A') + token.substring(i + 1);

        mvc.perform(get("/api/me").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, altered)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aTokenSignedWithAnotherKeyCannotClaimAdmin() throws Exception {
        User viewer = createUser("mallory", Role.VIEWER);
        String attackerKey = Base64.getEncoder().encodeToString("an-attacker-chosen-key-of-32-byt".getBytes());
        String forged = handMadeToken(attackerKey, viewer, Role.ADMIN, Instant.now().plusSeconds(600));

        mvc.perform(get("/api/admin/users").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, forged)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anExpiredTokenIsRejectedEvenWithTheRightSignature() throws Exception {
        User user = createUser("asha.rao", Role.VIEWER);
        String expired = handMadeToken(TEST_JWT_KEY, user, Role.VIEWER, Instant.now().minusSeconds(300));

        mvc.perform(get("/api/me").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, expired)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anUnsignedTokenIsRejected() throws Exception {
        // header {"alg":"none"} . claims {"sub":"1","username":"x","role":"ADMIN"} . (no signature)
        String unsigned = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"sub\":\"1\",\"username\":\"x\",\"role\":\"ADMIN\",\"exp\":9999999999}".getBytes())
                + ".";

        mvc.perform(get("/api/admin/users").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, unsigned)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anUnknownUrlIs404OnceLoggedIn() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        mvc.perform(get("/api/does-not-exist").cookie(accessCookie("asha.rao")))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------ refresh tokens

    @Test
    void refreshGivesANewPairOfTokens() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        MockHttpServletResponse loggedIn = login("asha.rao");
        Cookie firstRefresh = loggedIn.getCookie(AuthCookies.REFRESH_TOKEN);

        MockHttpServletResponse refreshed = refreshWith(firstRefresh);

        assertThat(refreshed.getStatus()).isEqualTo(204);
        Cookie secondRefresh = refreshed.getCookie(AuthCookies.REFRESH_TOKEN);
        assertThat(secondRefresh.getValue()).isNotEmpty().isNotEqualTo(firstRefresh.getValue());
        mvc.perform(get("/api/me").cookie(refreshed.getCookie(AuthCookies.ACCESS_TOKEN)))
                .andExpect(status().isOk());
    }

    @Test
    void reusingAnOldRefreshTokenRevokesTheWholeSession() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        Cookie stolen = login("asha.rao").getCookie(AuthCookies.REFRESH_TOKEN);
        Cookie current = refreshWith(stolen).getCookie(AuthCookies.REFRESH_TOKEN);

        // The old token is presented a second time: refused, and its cookies are cleared.
        MockHttpServletResponse replay = refreshWith(stolen);
        assertThat(replay.getStatus()).isEqualTo(401);
        assertThat(replay.getCookie(AuthCookies.REFRESH_TOKEN).getMaxAge()).isZero();

        // The revocation was really saved: the newest token is now dead too.
        assertThat(refreshWith(current).getStatus()).isEqualTo(401);
        assertThat(refreshTokens.findAll()).allSatisfy(t -> assertThat(t.getRevokedAt()).isNotNull());
    }

    @Test
    void refreshWithoutOrWithAMadeUpTokenIsRefused() throws Exception {
        mvc.perform(post("/api/auth/refresh")).andExpect(status().isUnauthorized());
        assertThat(refreshWith(new Cookie(AuthCookies.REFRESH_TOKEN, "made-up-value")).getStatus()).isEqualTo(401);
    }

    @Test
    void anExpiredRefreshTokenIsRefused() throws Exception {
        User user = createUser("asha.rao", Role.VIEWER);
        String raw = "an-old-token";
        refreshTokens.save(new RefreshToken(user.getId(), SessionService.fingerprint(raw),
                java.util.UUID.randomUUID(), Instant.now().minusSeconds(60)));

        assertThat(refreshWith(new Cookie(AuthCookies.REFRESH_TOKEN, raw)).getStatus()).isEqualTo(401);
    }

    @Test
    void logoutClearsTheCookiesAndKillsTheRefreshToken() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        Cookie refresh = login("asha.rao").getCookie(AuthCookies.REFRESH_TOKEN);

        MockHttpServletResponse loggedOut = mvc.perform(post("/api/auth/logout").cookie(refresh))
                .andExpect(status().isNoContent()).andReturn().getResponse();

        assertThat(loggedOut.getCookie(AuthCookies.ACCESS_TOKEN).getMaxAge()).isZero();
        assertThat(loggedOut.getCookie(AuthCookies.REFRESH_TOKEN).getMaxAge()).isZero();
        assertThat(refreshWith(refresh).getStatus()).isEqualTo(401);
    }

    // ------------------------------------------------------------------ roles

    @Test
    void onlyAdminsCanListUsers() throws Exception {
        createUser("vera.viewer", Role.VIEWER);
        createUser("anil.analyst", Role.ANALYST);
        createUser("adm.one", Role.ADMIN);

        mvc.perform(get("/api/admin/users").cookie(accessCookie("vera.viewer")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("You do not have permission to do this"));
        mvc.perform(get("/api/admin/users").cookie(accessCookie("anil.analyst")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/users").cookie(accessCookie("adm.one")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }

    @Test
    void anAdminCanPromoteAUserAndTheirOldSessionsEnd() throws Exception {
        User user = createUser("asha.rao", Role.VIEWER);
        createUser("adm.one", Role.ADMIN);
        Cookie ashaRefresh = login("asha.rao").getCookie(AuthCookies.REFRESH_TOKEN);

        mvc.perform(changeRole(user.getId(), "ANALYST").cookie(accessCookie("adm.one")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ANALYST"));

        assertThat(users.findByUsername("asha.rao").orElseThrow().getRole()).isEqualTo(Role.ANALYST);
        // The session opened as a VIEWER can no longer be renewed...
        assertThat(refreshWith(ashaRefresh).getStatus()).isEqualTo(401);
        // ...and a fresh login carries the new role.
        mvc.perform(get("/api/me").cookie(accessCookie("asha.rao")))
                .andExpect(jsonPath("$.role").value("ANALYST"));
    }

    @Test
    void aViewerCannotPromoteThemselves() throws Exception {
        User viewer = createUser("mallory", Role.VIEWER);

        mvc.perform(changeRole(viewer.getId(), "ADMIN").cookie(accessCookie("mallory")))
                .andExpect(status().isForbidden());
        assertThat(users.findByUsername("mallory").orElseThrow().getRole()).isEqualTo(Role.VIEWER);
    }

    @Test
    void roleChangeRejectsOwnAccountUnknownUserAndUnknownRole() throws Exception {
        User admin = createUser("adm.one", Role.ADMIN);
        User other = createUser("asha.rao", Role.VIEWER);
        Cookie adminCookie = accessCookie("adm.one");

        mvc.perform(changeRole(admin.getId(), "VIEWER").cookie(adminCookie))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("You cannot change your own role"));
        mvc.perform(changeRole(999_999L, "ANALYST").cookie(adminCookie)).andExpect(status().isNotFound());
        mvc.perform(changeRole(other.getId(), "SUPERUSER").cookie(adminCookie)).andExpect(status().isBadRequest());
        assertThat(users.findByUsername("asha.rao").orElseThrow().getRole()).isEqualTo(Role.VIEWER);
    }

    // ------------------------------------------------------------------ cross-site requests

    @Test
    void requestsFromAnotherWebsiteAreRefused() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        String body = "{\"username\":\"asha.rao\",\"password\":\"" + PASSWORD + "\"}";

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(body)
                .header("Origin", "https://evil.example"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Cross-site request refused"));
        mvc.perform(post("/api/auth/logout").header("Sec-Fetch-Site", "cross-site"))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestsFromOurOwnPagesAreAllowed() throws Exception {
        createUser("asha.rao", Role.VIEWER);
        String body = "{\"username\":\"asha.rao\",\"password\":\"" + PASSWORD + "\"}";

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(body)
                .header("Origin", "https://localhost:5173").header("Sec-Fetch-Site", "same-site"))
                .andExpect(status().isOk());
    }
}
