package com.securityanalyst.gateway.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

/**
 * Creates and checks access tokens (JWTs).
 *
 * A JWT is readable by anyone but cannot be altered: it carries a signature
 * made with a secret key only this server has (HMAC-SHA256). Changing a single
 * character of the token, or signing it with a different key, makes it invalid.
 */
@Service
public class JwtService {

    private static final int MIN_KEY_BYTES = 32;

    private final JwtEncoder encoder;
    private final JwtDecoder decoder;
    private final Duration lifetime;

    public JwtService(
            @Value("${security.jwt.signing-key}") String base64Key,
            @Value("${security.jwt.access-token-minutes}") long lifetimeMinutes) {
        SecretKey key = new SecretKeySpec(decodeKey(base64Key), "HmacSHA256");
        this.encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        // The decoder accepts HS256 only, so a token claiming "alg: none" or another algorithm is refused.
        this.decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        this.lifetime = Duration.ofMinutes(lifetimeMinutes);
    }

    public String issue(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(String.valueOf(user.getId()))
                .claim("username", user.getUsername())
                .claim("role", user.getRole().name())
                .issuedAt(now)
                .expiresAt(now.plus(lifetime))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    /** Returns the user a token belongs to, or empty if it is forged, altered, expired or malformed. */
    public Optional<AuthenticatedUser> verify(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            return Optional.of(new AuthenticatedUser(
                    Long.valueOf(jwt.getSubject()),
                    jwt.getClaimAsString("username"),
                    Role.valueOf(jwt.getClaimAsString("role"))));
        } catch (JwtException | IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }

    public Duration lifetime() {
        return lifetime;
    }

    private static byte[] decodeKey(String base64Key) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT_SIGNING_KEY must be Base64. Run scripts\\setup-secrets.ps1 to generate one.");
        }
        if (key.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("JWT_SIGNING_KEY is too short: it must be at least "
                    + MIN_KEY_BYTES + " random bytes. Run scripts\\setup-secrets.ps1 to generate one.");
        }
        return key;
    }
}
