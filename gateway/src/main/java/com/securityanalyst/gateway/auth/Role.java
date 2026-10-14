package com.securityanalyst.gateway.auth;

/** What a logged-in person is allowed to do. Must match the CHECK constraint on app_users.role. */
public enum Role {
    /** Manages users. */
    ADMIN,
    /** Submits incidents and approves or rejects actions. */
    ANALYST,
    /** Read-only. Every new account starts here. */
    VIEWER
}
