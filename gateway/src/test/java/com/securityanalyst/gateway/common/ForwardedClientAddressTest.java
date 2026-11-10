package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.TestCertificate;

/**
 * Behind the reverse proxy (step 19a, ADR-54), every request reaches the gateway from the proxy's
 * address. The proxy passes the visitor's address in X-Forwarded-For, and the gateway believes
 * that header only when the request really comes from the proxy; from anyone else it is ignored,
 * so nobody can dodge the per-address rate limits by writing a new address into it.
 *
 * These start the real web server (the header is handled by Tomcat itself, which simulated
 * requests skip), with a limit of 3 requests a minute per address. The test client connects from
 * 127.0.0.1, which plays the proxy in the first case and an outsider in the second.
 */
class ForwardedClientAddressTest {

    private static final TestCertificate CERTIFICATE = new TestCertificate();

    static void productionLikeSettings(DynamicPropertyRegistry registry, String trustedProxy) {
        CERTIFICATE.register(registry);
        registry.add("server.forward-headers-strategy", () -> "native");
        registry.add("server.tomcat.remoteip.internal-proxies", () -> trustedProxy);
        registry.add("security.rate-limit.requests-per-minute", () -> 3);
    }

    static int health(int port, String forwardedFor) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/health"))
                .header("X-Forwarded-For", forwardedFor).build();
        return CERTIFICATE.trustingClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Nested
    @SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
    class FromTheTrustedProxy extends PostgresIntegrationTest {

        @LocalServerPort
        private int port;

        @DynamicPropertySource
        static void settings(DynamicPropertyRegistry registry) {
            productionLikeSettings(registry, "127\\.0\\.0\\.1");
        }

        @Test
        void eachVisitorGetsTheirOwnLimit() throws Exception {
            for (int i = 0; i < 3; i++) {
                assertThat(health(port, "203.0.113.10")).isEqualTo(200);
            }
            assertThat(health(port, "203.0.113.10")).isEqualTo(429);

            // Another visitor, through the same proxy, is not affected by the first one's limit.
            assertThat(health(port, "203.0.113.11")).isEqualTo(200);
        }

        @Test
        void aVisitorCannotHideBehindAnAddressTheyWroteThemselves() throws Exception {
            // A visitor sends their own X-Forwarded-For; the proxy appends the real address after it.
            // The gateway takes the last address the proxy vouches for, never the visitor's invention.
            for (int i = 0; i < 3; i++) {
                assertThat(health(port, "198.51.100." + i + ", 203.0.113.20")).isEqualTo(200);
            }
            assertThat(health(port, "198.51.100.99, 203.0.113.20")).isEqualTo(429);
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
    class FromAnyoneElse extends PostgresIntegrationTest {

        @LocalServerPort
        private int port;

        @DynamicPropertySource
        static void settings(DynamicPropertyRegistry registry) {
            productionLikeSettings(registry, "10\\.255\\.255\\.254");   // a proxy that is not this client
        }

        @Test
        void theHeaderIsIgnoredAndTheConnectionsOwnAddressCounts() throws Exception {
            for (int i = 0; i < 3; i++) {
                assertThat(health(port, "203.0.113." + (30 + i))).isEqualTo(200);
            }
            // A fresh made-up address does not buy a fresh limit.
            assertThat(health(port, "203.0.113.99")).isEqualTo(429);
        }
    }
}
