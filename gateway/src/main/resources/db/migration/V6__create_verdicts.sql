-- The outcome of each investigation. The risk score is recomputed by the gateway from the
-- evidence it stored (ADR-9), and the final verdict is never lower than that score's band.
-- What the agent claimed is kept alongside, so a disagreement stays visible.
-- (The two reports, SOC and plain language, are added in step 13.)
CREATE TABLE verdicts (
    incident_id       BIGINT       PRIMARY KEY REFERENCES incidents (id) ON DELETE CASCADE,
    verdict           VARCHAR(10)  NOT NULL,
    attack_type       VARCHAR(30)  NOT NULL,
    risk_score        SMALLINT     NOT NULL,
    agent_verdict     VARCHAR(10)  NOT NULL,
    agent_risk_score  SMALLINT     NOT NULL,
    disagreement      BOOLEAN      NOT NULL,
    engine            VARCHAR(20)  NOT NULL,
    cited_evidence    JSONB        NOT NULL,
    counterfactual    VARCHAR(500) NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT ck_verdicts_verdict CHECK (verdict IN ('benign', 'suspicious', 'malicious')),
    CONSTRAINT ck_verdicts_agent_verdict CHECK (agent_verdict IN ('benign', 'suspicious', 'malicious')),
    CONSTRAINT ck_verdicts_attack_type CHECK (attack_type IN ('none', 'phishing', 'credential_stuffing',
        'brute_force', 'account_takeover', 'impossible_travel', 'vishing', 'prompt_injection', 'bec', 'other')),
    CONSTRAINT ck_verdicts_risk_score CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT ck_verdicts_agent_risk_score CHECK (agent_risk_score BETWEEN 0 AND 100),
    CONSTRAINT ck_verdicts_cited_evidence CHECK (jsonb_typeof(cited_evidence) = 'array')
);
