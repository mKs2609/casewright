package com.securityanalyst.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Starts the real web server (most tests only simulate it) with HTTPS switched on, and talks
 * to it the way a browser would, using a throwaway certificate (TestCertificate).
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class HttpsServerTest extends PostgresIntegrationTest {

    private static final TestCertificate CERTIFICATE = new TestCertificate();

    @LocalServerPort
    private int port;

    @DynamicPropertySource
    static void useTheThrowawayCertificate(DynamicPropertyRegistry registry) {
        CERTIFICATE.register(registry);
    }

    @Test
    void servesHttpsWithModernTlsAndTellsBrowsersToStayOnHttps() throws Exception {
        HttpResponse<String> response = CERTIFICATE.trustingClient()
                .send(HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/health")).build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.sslSession()).hasValueSatisfying(
                session -> assertThat(session.getProtocol()).isEqualTo("TLSv1.3"));
        // Spring only sends HSTS on HTTPS responses, so this header proves the request arrived encrypted.
        assertThat(response.headers().firstValue("Strict-Transport-Security"))
                .hasValue("max-age=31536000 ; includeSubDomains");
    }

    @Test
    void anUntrustedCertificateIsRejectedByTheClient() {
        // A client that has not been told to trust our self-signed certificate must refuse to connect.
        // This is what a browser warning is: the encryption works, but nobody vouches for the server.
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/health")).build();

        assertThatThrownBy(() -> HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()))
                .isInstanceOf(SSLHandshakeException.class);
    }

    @Test
    void plainHttpToTheHttpsPortIsRefused() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/health")).build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).doesNotContain("\"status\"");
    }
}
