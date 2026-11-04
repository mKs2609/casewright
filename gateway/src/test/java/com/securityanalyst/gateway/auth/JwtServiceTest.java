package com.securityanalyst.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

/** Token expiry, without Spring: tokens are signed here with the same key the service checks with. */
class JwtServiceTest {

    private final String key = randomKey();
    private final JwtService jwt = new JwtService(key, 15);

    private static String randomKey() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String tokenExpiringIn(Duration lifetime) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().subject("7").claim("username", "nina.example")
                .claim("role", "VIEWER").issuedAt(now.minusSeconds(120)).expiresAt(now.plus(lifetime)).build();
        return new NimbusJwtEncoder(new ImmutableSecret<>(new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256")))
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    @Test
    void aTokenWorksUntilItExpiresAndTellsWhen() {
        String token = tokenExpiringIn(Duration.ofMinutes(5));

        assertThat(jwt.verify(token)).hasValueSatisfying(user -> assertThat(user.username()).isEqualTo("nina.example"));
        assertThat(jwt.expiryOf(token)).hasValueSatisfying(expiry -> assertThat(expiry)
                .isBetween(Instant.now().plusSeconds(290), Instant.now().plusSeconds(301)));
    }

    @Test
    void aTokenThatExpiredASecondAgoIsRefused() {
        // The library's default would accept it for another minute.
        String token = tokenExpiringIn(Duration.ofSeconds(-1));

        assertThat(jwt.verify(token)).isEmpty();
        assertThat(jwt.expiryOf(token)).isEmpty();
    }

    @Test
    void aTokenSignedWithAnotherKeyHasNoExpiryEither() {
        String foreign = new JwtServiceTest().tokenExpiringIn(Duration.ofMinutes(5));

        assertThat(jwt.verify(foreign)).isEmpty();
        assertThat(jwt.expiryOf(foreign)).isEmpty();
    }
}
