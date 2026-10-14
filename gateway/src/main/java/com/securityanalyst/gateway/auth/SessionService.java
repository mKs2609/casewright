package com.securityanalyst.gateway.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.common.ApiException;

/**
 * Starts, renews and ends login sessions.
 *
 * A session is a pair of tokens: a short-lived access token (a JWT, checked
 * without the database) and a long-lived refresh token (random, remembered in
 * the database by its fingerprint so it can be cancelled).
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokens;
    private final UserRepository users;
    private final JwtService jwtService;
    private final Duration refreshLifetime;
    private final SecureRandom random = new SecureRandom();

    public SessionService(RefreshTokenRepository refreshTokens, UserRepository users, JwtService jwtService,
            @Value("${security.refresh-token-days}") long refreshTokenDays) {
        this.refreshTokens = refreshTokens;
        this.users = users;
        this.jwtService = jwtService;
        this.refreshLifetime = Duration.ofDays(refreshTokenDays);
    }

    /** The two tokens handed to the browser. The refresh token appears here in clear text exactly once. */
    public record Tokens(String accessToken, String refreshToken) {
    }

    /** Called after a successful login. */
    @Transactional
    public Tokens start(User user) {
        refreshTokens.deleteExpiredForUser(user.getId(), Instant.now());
        return issue(user, UUID.randomUUID());
    }

    /**
     * Swaps a refresh token for a new pair of tokens. Each refresh token works once.
     *
     * If a token that was already used is presented again, somebody has a copy
     * that should not exist (the real user or a thief, we can't tell which), so
     * every token from that login is revoked and both must log in again.
     *
     * noRollbackFor: this method throws to refuse the request, but the
     * revocation it just wrote must still be saved.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public Tokens refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw sessionExpired();
        }
        RefreshToken current = refreshTokens.findByTokenHash(fingerprint(rawRefreshToken))
                .orElseThrow(SessionService::sessionExpired);
        Instant now = Instant.now();

        boolean alreadyUsed = current.getRevokedAt() != null
                || refreshTokens.revokeIfActive(current.getId(), now) == 0;
        if (alreadyUsed) {
            refreshTokens.revokeFamily(current.getFamilyId(), now);
            log.warn("Refresh token reuse detected for user id {}; the whole session was revoked", current.getUserId());
            throw sessionExpired();
        }
        if (current.getExpiresAt().isBefore(now)) {
            throw sessionExpired();
        }
        // Re-read the user so a role change takes effect at the next refresh.
        User user = users.findById(current.getUserId()).orElseThrow(SessionService::sessionExpired);
        return issue(user, current.getFamilyId());
    }

    /** Called at logout: cancels every token from the same login. Unknown tokens are ignored. */
    @Transactional
    public void end(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        refreshTokens.findByTokenHash(fingerprint(rawRefreshToken))
                .ifPresent(token -> refreshTokens.revokeFamily(token.getFamilyId(), Instant.now()));
    }

    /** Called when a user's role changes: all their sessions must be renewed by logging in again. */
    @Transactional
    public void endAllFor(Long userId) {
        refreshTokens.revokeAllForUser(userId, Instant.now());
    }

    public Duration refreshLifetime() {
        return refreshLifetime;
    }

    private Tokens issue(User user, UUID familyId) {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        random.nextBytes(bytes);
        String rawRefreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        refreshTokens.save(new RefreshToken(user.getId(), fingerprint(rawRefreshToken), familyId,
                Instant.now().plus(refreshLifetime)));
        return new Tokens(jwtService.issue(user), rawRefreshToken);
    }

    /** SHA-256 is enough here (no salt or slow hash needed): the token is 256 random bits, not a guessable password. */
    static String fingerprint(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ApiException sessionExpired() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "Session expired. Please log in again.");
    }
}
