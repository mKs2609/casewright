-- People who log in to the product (analysts, viewers, admins).
-- The employees being protected live in a separate table, added later.
CREATE TABLE app_users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      VARCHAR(32)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(16)  NOT NULL DEFAULT 'VIEWER',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_app_users_username UNIQUE (username),
    CONSTRAINT ck_app_users_username CHECK (username ~ '^[a-z0-9._-]{3,32}$'),
    CONSTRAINT ck_app_users_role     CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER'))
);
