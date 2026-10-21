package com.securityanalyst.gateway.investigation;

/** The agent could not be reached, refused the call, or answered with something invalid. */
public class AgentException extends RuntimeException {

    public AgentException(String message) {
        super(message);
    }

    public AgentException(String message, Throwable cause) {
        super(message, cause);
    }
}
