package com.securityanalyst.gateway.investigation;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * One line of the agent's answer. Every line is checked against these shapes before the
 * gateway acts on it (ADR-5): the agent is treated as untrusted, like any caller.
 * An unknown "type", an unknown or missing field, or a value outside the allowed ones
 * makes the whole answer invalid.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AgentEvent.Thought.class, name = "agent.thought"),
        @JsonSubTypes.Type(value = AgentEvent.Complete.class, name = "investigation.complete") })
public sealed interface AgentEvent {

    /** No control characters (such as line breaks): agent text ends up in logs, and must not fake extra lines. */
    String PRINTABLE = "^[^\\p{Cntrl}]*$";

    /** A short note on what the agent is doing. */
    record Thought(
            @NotNull @Size(min = 1, max = 500) @Pattern(regexp = PRINTABLE) String text) implements AgentEvent {
    }

    /**
     * The last event of every investigation. "result" is the status the incident moves to,
     * so it is limited to the statuses the agent is allowed to choose: it can never, say,
     * mark an incident "closed" by itself.
     */
    record Complete(
            @NotNull @Pattern(regexp = "^needs_review$") String result,
            @NotNull @Pattern(regexp = "^stub$") String engine) implements AgentEvent {
    }
}
