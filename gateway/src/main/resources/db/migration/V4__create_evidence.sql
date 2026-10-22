-- The evidence chain: one row per tool call the agent made for an incident.
-- Accepted calls are evidence E1, E2, ...; refused ones (guardrails) are R1, R2, ... with
-- the reason. Verdicts and reports will cite these labels, so every claim can be traced
-- back to the evidence behind it.
CREATE TABLE evidence (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id  BIGINT       NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    label        VARCHAR(4)   NOT NULL,
    tool         VARCHAR(40)  NOT NULL,
    args         JSONB        NOT NULL,
    status       VARCHAR(10)  NOT NULL,
    summary      VARCHAR(500),
    result       JSONB,
    -- Findings: [{id, label (technical), plain, weight, mitre, indicator}, ...]
    signals      JSONB        NOT NULL DEFAULT '[]',
    reason       VARCHAR(500),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_evidence_incident_label UNIQUE (incident_id, label),
    CONSTRAINT ck_evidence_label CHECK (label ~ '^[ER][1-9][0-9]{0,2}$'),
    CONSTRAINT ck_evidence_status CHECK (status IN ('ok', 'rejected')),
    CONSTRAINT ck_evidence_args_object CHECK (jsonb_typeof(args) = 'object'),
    CONSTRAINT ck_evidence_signals_array CHECK (jsonb_typeof(signals) = 'array'),
    -- An accepted call (E) has a summary and a result; a refused one (R) has a reason and no result.
    CONSTRAINT ck_evidence_shape CHECK (
        (status = 'ok' AND label LIKE 'E%' AND summary IS NOT NULL AND jsonb_typeof(result) = 'object' AND reason IS NULL)
        OR
        (status = 'rejected' AND label LIKE 'R%' AND reason IS NOT NULL AND result IS NULL
            AND summary IS NULL AND signals = '[]'::jsonb))
);

CREATE INDEX ix_evidence_incident_id ON evidence (incident_id);
