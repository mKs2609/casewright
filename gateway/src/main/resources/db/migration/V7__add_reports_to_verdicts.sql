-- The two reports (step 13, ADR-45): one for the security team, one for the employee, both
-- built from the same evidence chain and checked against the stored evidence before saving.
-- Verdicts recorded before this step have none, so the columns allow NULL.
ALTER TABLE verdicts
    ADD COLUMN soc_report   JSONB,
    ADD COLUMN plain_report JSONB,
    ADD CONSTRAINT ck_verdicts_soc_report CHECK (soc_report IS NULL OR jsonb_typeof(soc_report) = 'object'),
    ADD CONSTRAINT ck_verdicts_plain_report CHECK (plain_report IS NULL OR jsonb_typeof(plain_report) = 'object');
