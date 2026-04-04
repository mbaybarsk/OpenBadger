CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    job_id TEXT NULL REFERENCES jobs(id) ON DELETE SET NULL,
    node_id TEXT NULL REFERENCES nodes(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('asset', 'sighting', 'relationship')),
    observed_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT observations_payload_object CHECK (jsonb_typeof(payload) = 'object')
);
