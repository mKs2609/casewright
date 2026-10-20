-- Employees the product protects (NOT the people who log in to it), with their
-- behavioural baseline: usual countries, working hours, devices and contacts.
-- The baseline is encrypted by the gateway before it is stored (AES-256-GCM, ADR-37),
-- so this column only ever holds unreadable bytes; the key is never in the database.
CREATE TABLE monitored_identities (
    identity      VARCHAR(64)  PRIMARY KEY,
    display_name  VARCHAR(100) NOT NULL,
    baseline      BYTEA        NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT ck_monitored_identities_identity CHECK (identity ~ '^[a-z0-9][a-z0-9._-]{0,63}$')
);

-- One suspicious event to investigate. The kind-specific details (an email's sender and
-- body, a batch of login events, a call transcript) are stored as JSON exactly as
-- submitted, after validation.
CREATE TABLE incidents (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind              VARCHAR(20) NOT NULL,
    subject_identity  VARCHAR(64) NOT NULL REFERENCES monitored_identities (identity),
    payload           JSONB       NOT NULL,
    status            VARCHAR(20) NOT NULL DEFAULT 'queued',
    -- Where it came from: 'api' for now; demo scenarios come later.
    source            VARCHAR(40) NOT NULL,
    created_by        BIGINT      NOT NULL REFERENCES app_users (id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_incidents_kind CHECK (kind IN ('email', 'login', 'call_transcript')),
    CONSTRAINT ck_incidents_status CHECK (status IN
        ('queued', 'investigating', 'awaiting_approval', 'needs_review', 'closed', 'error')),
    CONSTRAINT ck_incidents_payload_is_object CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX ix_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX ix_incidents_subject_identity ON incidents (subject_identity);
