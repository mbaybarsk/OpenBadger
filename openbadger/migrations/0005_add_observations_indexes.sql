CREATE INDEX IF NOT EXISTS observations_site_id_idx ON observations (site_id);

CREATE INDEX IF NOT EXISTS observations_type_idx ON observations (type);

CREATE INDEX IF NOT EXISTS observations_observed_at_idx ON observations (observed_at);

CREATE INDEX IF NOT EXISTS observations_payload_gin_idx ON observations USING GIN (payload);
