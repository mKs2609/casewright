package com.securityanalyst.gateway.demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import com.securityanalyst.gateway.incident.IncidentRequest;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The demo scenarios (FR-26), from demo/scenarios.json. The file is made from the agent's test
 * scenarios, whose verdicts are known, and an agent test checks that the two still match.
 *
 * Each incident is read and validated exactly like a body sent to POST /api/incidents, at
 * startup: a broken scenario stops the gateway instead of failing in front of an audience.
 * All of it is fictional and uses reserved example names only.
 */
@Component
@ConditionalOnProperty(name = "demo.enabled", havingValue = "true")
public class DemoScenarios {

    /** What a demo button shows. Never the incident itself. */
    public record Scenario(String name, String title, String description) {
    }

    /** One entry of the file, as written. */
    record Stored(String name, String title, String description, JsonNode incident) {
    }

    record ScenarioFile(List<Stored> scenarios) {
    }

    private static final String NAME = "^[a-z_]{1,40}$";

    private final Map<String, Scenario> shown = new LinkedHashMap<>();
    private final Map<String, IncidentRequest> incidents = new LinkedHashMap<>();

    @Autowired
    public DemoScenarios(JsonMapper json, Validator validator) {
        this(json, validator, new ClassPathResource("demo/scenarios.json"));
    }

    /** Tests pass their own file. */
    DemoScenarios(JsonMapper json, Validator validator, Resource file) {
        ScenarioFile read;
        try (InputStream in = file.getInputStream()) {
            read = json.readValue(in, ScenarioFile.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the demo scenarios", e);
        }
        if (read.scenarios() == null || read.scenarios().isEmpty()) {
            throw new IllegalStateException("The demo scenarios file has no scenarios");
        }
        for (Stored stored : read.scenarios()) {
            if (stored.name() == null || !stored.name().matches(NAME) || shown.containsKey(stored.name())) {
                throw new IllegalStateException("A demo scenario has a missing, malformed or repeated name");
            }
            if (stored.title() == null || stored.title().isBlank() || stored.description() == null) {
                throw new IllegalStateException("Demo scenario " + stored.name() + " needs a title and a description");
            }
            IncidentRequest incident = json.treeToValue(stored.incident(), IncidentRequest.class);
            var problems = validator.validate(incident);
            if (!problems.isEmpty()) {
                throw new IllegalStateException("Demo scenario " + stored.name() + " is not a valid incident: "
                        + problems.stream().map(ConstraintViolation::getPropertyPath).map(String::valueOf)
                                .sorted().collect(Collectors.joining(", ")));
            }
            shown.put(stored.name(), new Scenario(stored.name(), stored.title(), stored.description()));
            incidents.put(stored.name(), incident);
        }
    }

    /** The scenarios in button order: the first is the main one ("Attempt breach"). */
    public List<Scenario> list() {
        return List.copyOf(shown.values());
    }

    public Optional<IncidentRequest> incident(String name) {
        return Optional.ofNullable(incidents.get(name));
    }
}
