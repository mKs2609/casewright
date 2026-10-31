-- The tamper-evident history of the system (ADR-11, ADR-46). Each entry's hash is an HMAC over
-- the entry and the previous entry's hash, with a key kept outside the database.
-- seq is assigned by the gateway under a lock, so it has no gaps: a missing number means a
-- missing entry. incident_id has no foreign key on purpose: the history outlives what it describes.
CREATE TABLE audit_log (
    seq          BIGINT       PRIMARY KEY,
    ts           TIMESTAMPTZ  NOT NULL,
    actor        VARCHAR(40)  NOT NULL,
    event        VARCHAR(40)  NOT NULL,
    incident_id  BIGINT,
    data         JSONB        NOT NULL,
    prev_hash    CHAR(64)     NOT NULL,
    hash         CHAR(64)     NOT NULL,

    CONSTRAINT ck_audit_log_seq CHECK (seq > 0),
    CONSTRAINT ck_audit_log_event CHECK (event ~ '^[a-z_.]+$'),
    CONSTRAINT ck_audit_log_data CHECK (jsonb_typeof(data) = 'object')
);

CREATE INDEX ix_audit_log_incident_id ON audit_log (incident_id);

-- Entries are only ever added. This stops mistakes and casual edits; the application's role owns
-- the table and could switch the trigger off (ADR-18), which is what the hash chain is for.
CREATE FUNCTION audit_log_refuse_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'The audit log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();

CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_change();
