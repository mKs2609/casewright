package com.securityanalyst.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Starts the real web server (most tests only simulate it) with HTTPS switched on, and talks
 * to it the way a browser would. Before starting, it makes a throwaway certificate with the JDK's
 * keytool, exactly like scripts/setup-https.ps1 does, so the test needs no files or secrets.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class HttpsServerTest extends PostgresIntegrationTest {

    private static final String KEYSTORE_PASSWORD = randomPassword();
    private static final Path KEYSTORE = createKeyStore();

    @LocalServerPort
    private int port;

    @DynamicPropertySource
    static void useTheThrowawayCertificate(DynamicPropertyRegistry registry) {
        registry.add("server.ssl.key-store", () -> "file:" + KEYSTORE);
        registry.add("server.ssl.key-store-password", () -> KEYSTORE_PASSWORD);
    }

    @Test
    void servesHttpsWithModernTlsAndTellsBrowsersToStayOnHttps() throws Exception {
        HttpResponse<String> response = trustingOurCertificate()
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

    /** A client that trusts exactly one certificate: the throwaway one this test made. */
    private static HttpClient trustingOurCertificate() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(KEYSTORE)) {
            keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());
        }
        KeyStore trusted = KeyStore.getInstance("PKCS12");
        trusted.load(null, null);
        trusted.setCertificateEntry("gateway", keyStore.getCertificate("gateway"));

        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trusted);
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, trustManagers.getTrustManagers(), null);
        return HttpClient.newBuilder().sslContext(tls).build();
    }

    private static String randomPassword() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Path createKeyStore() {
        try {
            Path dir = Files.createTempDirectory("gateway-https-test");
            Path keyStore = dir.resolve("test.p12");
            dir.toFile().deleteOnExit();
            keyStore.toFile().deleteOnExit();
            String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
            ProcessBuilder builder = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "gateway",
                    "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA", "-validity", "1",
                    "-storetype", "PKCS12", "-keystore", keyStore.toString(), "-storepass:env", "TEST_KEYSTORE_PASSWORD",
                    "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-ext", "BC:c=ca:false"))
                    .redirectErrorStream(true);
            builder.environment().put("TEST_KEYSTORE_PASSWORD", KEYSTORE_PASSWORD);
            Process process = builder.start();
            String output = new String(process.getInputStream().readAllBytes());
            if (process.waitFor() != 0) {
                throw new IllegalStateException("keytool failed: " + output);
            }
            return keyStore;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
