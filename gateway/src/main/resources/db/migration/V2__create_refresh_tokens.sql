-- Refresh tokens: long-lived tokens used only to obtain a new access token.
-- Only a SHA-256 fingerprint is stored, so a copy of this table cannot be used to log in.
CREATE TABLE refresh_tokens (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES app_users (id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,
    -- Every token that descends from one login shares a family. If an old token
    -- is ever presented again, the whole family is revoked.
    family_id   UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,

    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens (family_id);
