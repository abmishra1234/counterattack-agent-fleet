SELECT id, outcome, safe_error_code, budget_estimate_usd, attempt_number
FROM llm_calls WHERE id = 'recovery-call';
SELECT id, status, attempt, max_attempts, lease_owner
FROM jobs WHERE id = 'recovery-job';
SELECT sequence_number, event_type, outcome
FROM audit_events ORDER BY sequence_number;
