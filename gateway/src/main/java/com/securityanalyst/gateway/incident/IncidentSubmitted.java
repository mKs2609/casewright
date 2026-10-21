package com.securityanalyst.gateway.incident;

/** Announced when an incident has been stored; the investigation starts once it is committed. */
public record IncidentSubmitted(Long incidentId) {
}
