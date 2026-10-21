package com.securityanalyst.gateway.investigation;

import java.net.URI;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * How to reach the agent, from the {@code agent.*} settings (ADR-4).
 *
 * @param baseUrl              where the agent listens; on this machine only (127.0.0.1)
 * @param serviceToken         the shared secret sent with every call (AGENT_SERVICE_TOKEN)
 * @param connectTimeout       give up quickly if the agent is not running
 * @param investigationTimeout the longest one whole investigation may take, answer included
 */
@ConfigurationProperties("agent")
@Validated
public record AgentProperties(
        @NotNull URI baseUrl,
        @NotNull @Size(min = 32, message = "must be at least 32 characters (run scripts\\setup-secrets.ps1)") String serviceToken,
        @NotNull Duration connectTimeout,
        @NotNull Duration investigationTimeout) {

    /** Records print all their fields by default. Never let the token reach a log. */
    @Override
    public String toString() {
        return "AgentProperties[baseUrl=" + baseUrl + ", serviceToken=<hidden>, connectTimeout=" + connectTimeout
                + ", investigationTimeout=" + investigationTimeout + "]";
    }
}
