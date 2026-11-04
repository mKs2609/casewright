package com.securityanalyst.gateway;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * A throwaway certificate for tests that start the real HTTPS server. It is made with the JDK's
 * keytool, exactly like scripts/setup-https.ps1 does, so those tests need no files or secrets.
 */
public final class TestCertificate {

    private final String password = randomPassword();
    private final Path keyStore = create(password);

    /** Points the server at this certificate. */
    public void register(DynamicPropertyRegistry registry) {
        registry.add("server.ssl.key-store", () -> "file:" + keyStore);
        registry.add("server.ssl.key-store-password", () -> password);
    }

    /** A client that trusts exactly one certificate: this one. */
    public HttpClient trustingClient() {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(keyStore)) {
                store.load(in, password.toCharArray());
            }
            KeyStore trusted = KeyStore.getInstance("PKCS12");
            trusted.load(null, null);
            trusted.setCertificateEntry("gateway", store.getCertificate("gateway"));

            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trusted);
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, trustManagers.getTrustManagers(), null);
            return HttpClient.newBuilder().sslContext(tls).build();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String randomPassword() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Path create(String password) {
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
            builder.environment().put("TEST_KEYSTORE_PASSWORD", password);
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
