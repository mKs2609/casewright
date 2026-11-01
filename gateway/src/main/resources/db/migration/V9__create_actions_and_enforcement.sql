-- Response actions (step 15, ADR-47). Low-risk ones run at once; high-risk ones wait as 'pending'
-- until a person decides, or until they expire.
CREATE TABLE actions (
    id           BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id  BIGINT       NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    action       VARCHAR(30)  NOT NULL,
    target       VARCHAR(254) NOT NULL,
    risk         VARCHAR(4)   NOT NULL,
    status       VARCHAR(8)   NOT NULL,
    evidence     VARCHAR(4)   NOT NULL,
    decided_by   BIGINT       REFERENCES app_users (id) ON DELETE SET NULL,
    decided_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_actions_incident_action_target UNIQUE (incident_id, action, target),
    CONSTRAINT ck_actions_action CHECK (action IN ('monitor', 'notify_user', 'force_password_reset', 'lock_account',
        'block_ip', 'quarantine_email', 'block_sender_domain', 'block_phone_number')),
    CONSTRAINT ck_actions_risk CHECK (risk IN ('low', 'high')),
    CONSTRAINT ck_actions_status CHECK (status IN ('pending', 'executed', 'rejected', 'expired')),
    -- A high-risk action never runs by itself: it starts as pending, and pending always has a deadline.
    CONSTRAINT ck_actions_pending_expires CHECK (status <> 'pending' OR expires_at IS NOT NULL)
);

CREATE INDEX ix_actions_incident_id ON actions (incident_id);
CREATE INDEX ix_actions_pending ON actions (expires_at) WHERE status = 'pending';

-- What the (simulated) enforcement layer has done (ADR-13): nothing real is blocked or locked.
CREATE TABLE enforcement (
    id          BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_id   BIGINT       NOT NULL REFERENCES actions (id) ON DELETE CASCADE,
    action      VARCHAR(30)  NOT NULL,
    target      VARCHAR(254) NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_enforcement_action UNIQUE (action_id)
);
