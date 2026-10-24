package com.securityanalyst.gateway.investigation;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.securityanalyst.gateway.common.IpAddress;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.JsonNode;

/**
 * One line of the agent's answer. Every line is checked against these shapes before the
 * gateway acts on it (ADR-5): the agent is treated as untrusted, like any caller.
 * An unknown "type", an unknown or missing field, or a value outside the allowed ones
 * makes the whole answer invalid.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AgentEvent.Thought.class, name = "agent.thought"),
        @JsonSubTypes.Type(value = AgentEvent.Indicators.class, name = "incident.indicators"),
        @JsonSubTypes.Type(value = AgentEvent.Step.class, name = "agent.step"),
        @JsonSubTypes.Type(value = AgentEvent.Guardrail.class, name = "agent.guardrail"),
        @JsonSubTypes.Type(value = AgentEvent.Complete.class, name = "investigation.complete") })
public sealed interface AgentEvent {

    /** No control characters (such as line breaks): agent text ends up in logs, and must not fake extra lines. */
    String PRINTABLE = "^[^\\p{Cntrl}]*$";

    /** The tools the agent may use. A step naming any other tool is refused. */
    String KNOWN_TOOLS = "^(reputation_lookup|baseline_check|pattern_match|correlate_events)$";

    /** A short note on what the agent is doing. */
    record Thought(
            @NotNull @Size(min = 1, max = 500) @Pattern(regexp = PRINTABLE) String text) implements AgentEvent {
    }

    /** The indicators found in the incident, kept by the gateway for later correlation. */
    record Indicators(@NotNull @Size(max = 200) List<@NotNull @Valid Indicator> indicators) implements AgentEvent {
    }

    /** One indicator. Its value must really look like its type (an IP address, a domain, ...). */
    record Indicator(
            @NotNull @Pattern(regexp = "^(ip|domain|email|phone)$") String type,
            @NotNull @Size(min = 1, max = 254) @Pattern(regexp = PRINTABLE) String value) {

        private static final java.util.regex.Pattern DOMAIN = java.util.regex.Pattern.compile(
                "^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}$");
        private static final java.util.regex.Pattern EMAIL = java.util.regex.Pattern.compile(
                "^[a-z0-9._%+-]{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}$");
        private static final java.util.regex.Pattern PHONE = java.util.regex.Pattern.compile("^\\+?[0-9]{6,15}$");

        @JsonIgnore
        @AssertTrue(message = "does not look like its type")
        public boolean isWellFormed() {
            if (type == null || value == null) {
                return true;   // reported by @NotNull instead
            }
            return switch (type) {
                case "ip" -> new IpAddress.Validator().isValid(value, null);
                case "domain" -> DOMAIN.matcher(value).matches();
                case "email" -> EMAIL.matcher(value).matches();
                case "phone" -> PHONE.matcher(value).matches();
                default -> false;
            };
        }
    }

    /** One finding, in a technical voice (label) and a plain one (plain). */
    record Signal(
            @NotNull @Pattern(regexp = "^[A-Z][A-Z0-9-]{1,39}$") String id,
            @NotNull @Size(min = 1, max = 300) @Pattern(regexp = PRINTABLE) String label,
            @NotNull @Size(min = 1, max = 300) @Pattern(regexp = PRINTABLE) String plain,
            @NotNull @Min(0) @Max(100) Integer weight,
            @Pattern(regexp = "^(T\\d{4}(\\.\\d{3})?|AML\\.T\\d{4}(\\.\\d{3})?)$") String mitre,
            @Size(max = 254) @Pattern(regexp = PRINTABLE) String indicator) {
    }

    /** An accepted tool call: evidence E1, E2, ... */
    record Step(
            @NotNull @Pattern(regexp = "^E[1-9][0-9]{0,2}$") String label,
            @NotNull @Pattern(regexp = KNOWN_TOOLS) String tool,
            @NotNull @Size(max = 4) Map<@Pattern(regexp = "^[a-zA-Z]{1,40}$") String,
                    @NotNull @Size(max = 254) @Pattern(regexp = PRINTABLE) String> args,
            @NotNull @Size(min = 1, max = 500) @Pattern(regexp = PRINTABLE) String summary,
            @NotNull JsonNode result,
            @NotNull @Size(max = 20) List<@NotNull @Valid Signal> signals) implements AgentEvent {
    }

    /** A refused tool call: R1, R2, ..., with the reason. Recorded, never run. */
    record Guardrail(
            @NotNull @Pattern(regexp = "^R[1-9][0-9]{0,2}$") String label,
            @NotNull @Pattern(regexp = "^[a-z_]{1,40}$") String tool,
            @NotNull @Size(max = 4) Map<@Pattern(regexp = "^[a-zA-Z]{1,40}$") String,
                    @NotNull @Size(max = 254) @Pattern(regexp = PRINTABLE) String> args,
            @NotNull @Size(min = 1, max = 500) @Pattern(regexp = PRINTABLE) String reason) implements AgentEvent {
    }

    /**
     * The last event of every investigation. "result" is the status the incident moves to,
     * so it is limited to the statuses the agent is allowed to choose: it can never, say,
     * mark an incident "closed" by itself.
     */
    record Complete(
            @NotNull @Pattern(regexp = "^needs_review$") String result,
            @NotNull @Pattern(regexp = "^rules$") String engine) implements AgentEvent {
    }
}
