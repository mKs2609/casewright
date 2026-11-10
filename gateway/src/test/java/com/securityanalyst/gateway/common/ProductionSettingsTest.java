package com.securityanalyst.gateway.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * The production settings (application-production.properties) and the server's layout
 * (deploy/compose.yaml) must agree (step 19a, ADR-54). Nothing else would notice if they drifted
 * apart: everything would still start, and every visitor would silently share one rate limit.
 */
class ProductionSettingsTest {

    private static final Path COMPOSE = Path.of("..", "deploy", "compose.yaml");

    private static Properties production() throws Exception {
        Properties settings = new Properties();
        try (InputStream in = ProductionSettingsTest.class.getResourceAsStream("/application-production.properties")) {
            settings.load(in);
        }
        return settings;
    }

    private static String compose() throws Exception {
        return Files.readString(COMPOSE);
    }

    @Test
    void theGatewayBelievesVisitorAddressesFromCaddysFixedAddressAndNoOtherOne() throws Exception {
        Matcher caddy = Pattern.compile("ipv4_address: (\\d+\\.\\d+\\.\\d+\\.\\d+)").matcher(compose());
        assertThat(caddy.find()).as("Caddy has a fixed address in compose.yaml").isTrue();
        String caddyAddress = caddy.group(1);
        assertThat(caddy.find()).as("only one fixed address").isFalse();

        Properties settings = production();
        assertThat(settings.getProperty("server.forward-headers-strategy")).isEqualTo("native");
        Pattern trusted = Pattern.compile(settings.getProperty("server.tomcat.remoteip.internal-proxies"));
        assertThat(trusted.matcher(caddyAddress).matches()).isTrue();
        // Nothing else on that network, nor a visitor's own address, is believed.
        assertThat(trusted.matcher("172.30.0.11").matches()).isFalse();
        assertThat(trusted.matcher("172.30.0.100").matches()).isFalse();
        assertThat(trusted.matcher("203.0.113.10").matches()).isFalse();
    }

    @Test
    void theKeystoreIsWhereTheCertificateServicePutsIt() throws Exception {
        assertThat(production().getProperty("server.ssl.key-store")).isEqualTo("file:/certs/gateway.p12");
        assertThat(compose()).contains("gateway-keystore:/certs:ro")
                .containsPattern(Pattern.compile("gateway-keystore:/certs\\r?$", Pattern.MULTILINE));
    }

    @Test
    void theAllowedOriginIsTheSitesOwnAddress() throws Exception {
        assertThat(production().getProperty("security.allowed-origins")).isEqualTo("${PUBLIC_ORIGIN}");
        assertThat(compose()).contains("PUBLIC_ORIGIN: ${PUBLIC_ORIGIN:?missing in deploy/.env}");
    }

    @Test
    void theAgentRunsWithoutAnAiModelOnTheServer() throws Exception {
        assertThat(compose()).contains("LLM_PROVIDER: \"off\"").contains("network_mode: \"service:gateway\"");
    }
}
