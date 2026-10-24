-- The indicators found in each incident (IP addresses, domains, email addresses, phone
-- numbers), as reported by the agent and checked by the gateway. Later investigations are
-- told which recent incidents share them, to spot one attacker hitting several people.
CREATE TABLE incident_indicators (
    incident_id  BIGINT       NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    type         VARCHAR(6)   NOT NULL,
    value        VARCHAR(254) NOT NULL,

    PRIMARY KEY (incident_id, type, value),
    CONSTRAINT ck_incident_indicators_type CHECK (type IN ('ip', 'domain', 'email', 'phone'))
);

-- "Which incidents contain this value?" is the question correlation asks.
CREATE INDEX ix_incident_indicators_type_value ON incident_indicators (type, value);
