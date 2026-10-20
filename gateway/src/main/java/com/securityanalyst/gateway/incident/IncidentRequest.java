package com.securityanalyst.gateway.incident;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * The JSON body of POST /api/incidents. The "kind" field decides which shape the rest of
 * the body must have, and so which record it is read into:
 *
 *   {"kind": "email", ...}  -> EmailIncidentRequest
 *   {"kind": "login", ...}  -> LoginIncidentRequest
 *   {"kind": "call_transcript", ...}  -> CallTranscriptIncidentRequest
 *
 * A missing or unknown kind, or any field the chosen record does not declare, is refused
 * before a controller ever runs. Each record then carries its own validation rules.
 *
 * "sealed ... permits" lists every kind that exists. Adding a kind means adding it here
 * and in @JsonSubTypes; the compiler then points at every switch that must handle it.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "kind")
@JsonSubTypes({
        @JsonSubTypes.Type(value = EmailIncidentRequest.class, name = "email"),
        @JsonSubTypes.Type(value = LoginIncidentRequest.class, name = "login"),
        @JsonSubTypes.Type(value = CallTranscriptIncidentRequest.class, name = "call_transcript") })
public sealed interface IncidentRequest permits EmailIncidentRequest, LoginIncidentRequest, CallTranscriptIncidentRequest {

    /** A monitored identity, e.g. "priya.sharma". Same rule as the database column. */
    String IDENTITY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,63}$";
    String IDENTITY_MESSAGE = "must be a monitored identity such as priya.sharma";

    /** The employee this incident is about. */
    String subjectIdentity();
}
