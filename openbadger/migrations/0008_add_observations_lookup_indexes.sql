CREATE INDEX IF NOT EXISTS observations_job_id_idx ON observations (job_id);

CREATE INDEX IF NOT EXISTS observations_node_id_idx ON observations (node_id);

CREATE INDEX IF NOT EXISTS observations_scope_idx ON observations (scope);
