package com.securityanalyst.gateway.investigation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;

/**
 * Calls the agent and reads its answer, one event per line.
 *
 * The agent is treated as untrusted (ADR-5), so the answer is read defensively:
 * - every line must be a valid {@link AgentEvent} (checked by Jackson, then Bean Validation);
 * - a line may be at most 64 KB and an answer at most 1000 lines, so a broken or
 *   compromised agent cannot exhaust the gateway's memory;
 * - the whole investigation, answer included, has a deadline; a watchdog closes the
 *   connection when it passes, so an agent that goes silent cannot block forever;
 * - "investigation.complete" must come last, exactly once.
 */
@Component
@EnableConfigurationProperties(AgentProperties.class)
public class AgentClient {

    static final int MAX_LINE_BYTES = 64 * 1024;
    static final int MAX_EVENTS = 1000;

    private final AgentProperties agent;
    private final HttpClient http;
    private final JsonMapper json;
    private final ObjectReader eventReader;
    private final Validator validator;
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "agent-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    public AgentClient(AgentProperties agent, JsonMapper json, Validator validator) {
        this.agent = agent;
        this.json = json;
        this.validator = validator;
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(agent.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        // Strict on purpose, whatever the application-wide settings are.
        this.eventReader = json.readerFor(AgentEvent.class)
                .with(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(StreamReadFeature.STRICT_DUPLICATE_DETECTION);
    }

    /**
     * Runs one investigation, passing each valid event to {@code onEvent} as it arrives.
     *
     * @return the final event
     * @throws AgentException if the agent is unreachable, refuses, or answers with anything invalid
     */
    public AgentEvent.Complete investigate(AgentRequest request, Consumer<AgentEvent> onEvent) {
        HttpRequest call = HttpRequest.newBuilder(agent.baseUrl().resolve("/internal/investigate"))
                .timeout(agent.investigationTimeout())
                .header("Authorization", "Bearer " + agent.serviceToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(request)))
                .build();

        HttpResponse<InputStream> response;
        try {
            response = http.send(call, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new AgentException("Could not reach the agent at " + agent.baseUrl() + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AgentException("Interrupted while calling the agent", e);
        }

        try (InputStream body = response.body()) {
            if (response.statusCode() != 200) {
                throw new AgentException("The agent answered " + response.statusCode());
            }
            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (!contentType.startsWith("application/x-ndjson")) {
                throw new AgentException("The agent answered with an unexpected content type");
            }
            ScheduledFuture<?> deadline = watchdog.schedule(() -> closeQuietly(body),
                    agent.investigationTimeout().toMillis(), TimeUnit.MILLISECONDS);
            try {
                return readEvents(body, onEvent);
            } finally {
                deadline.cancel(false);
            }
        } catch (IOException e) {
            throw new AgentException("The agent's answer was cut off or took too long", e);
        }
    }

    private AgentEvent.Complete readEvents(InputStream body, Consumer<AgentEvent> onEvent) throws IOException {
        AgentEvent.Complete complete = null;
        int count = 0;
        String line;
        while ((line = readLine(body)) != null) {
            if (line.isBlank()) {
                continue;
            }
            if (complete != null) {
                throw new AgentException("The agent sent events after investigation.complete");
            }
            if (++count > MAX_EVENTS) {
                throw new AgentException("The agent sent more than " + MAX_EVENTS + " events");
            }
            AgentEvent event = parse(line);
            if (event instanceof AgentEvent.Complete last) {
                complete = last;
            }
            onEvent.accept(event);
        }
        if (complete == null) {
            throw new AgentException("The agent's answer ended without investigation.complete");
        }
        return complete;
    }

    AgentEvent parse(String line) {
        AgentEvent event;
        try {
            event = eventReader.readValue(line);
        } catch (JacksonException e) {
            // The original message quotes the line; keep only its kind of problem.
            throw new AgentException("The agent sent an event that is not valid (" + e.getClass().getSimpleName() + ")");
        }
        Set<ConstraintViolation<AgentEvent>> violations = validator.validate(event);
        if (!violations.isEmpty()) {
            ConstraintViolation<AgentEvent> first = violations.iterator().next();
            throw new AgentException("The agent sent an event with an invalid " + first.getPropertyPath());
        }
        return event;
    }

    /** One line as UTF-8, without the line break; null at the end. Refuses lines over the limit. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                return bytes.toString(StandardCharsets.UTF_8);
            }
            if (bytes.size() >= MAX_LINE_BYTES) {
                throw new AgentException("The agent sent a line longer than " + MAX_LINE_BYTES + " bytes");
            }
            bytes.write(b);
        }
        return bytes.size() == 0 ? null : bytes.toString(StandardCharsets.UTF_8);
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException ignored) {
            // Closing is only used to unblock a read that has run out of time.
        }
    }
}
