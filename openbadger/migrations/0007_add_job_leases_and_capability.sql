ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS capability TEXT NOT NULL DEFAULT '';

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS lease_owner_node_id TEXT NULL REFERENCES nodes(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_jobs_lease_candidates
    ON jobs (site_id, capability, created_at, id)
    WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS idx_jobs_lease_expires_at
    ON jobs (lease_expires_at);
