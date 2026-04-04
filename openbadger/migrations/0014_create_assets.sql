CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    provisional BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_site_last_seen
    ON assets (site_id, last_seen DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS asset_identifiers (
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    last_observation_id TEXT REFERENCES observations(observation_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_asset_identifiers_lookup
    ON asset_identifiers (site_id, kind, value);

CREATE INDEX IF NOT EXISTS idx_asset_identifiers_asset
    ON asset_identifiers (asset_id, kind, value);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_identifiers_site_kind_value_strong
    ON asset_identifiers (site_id, kind, value)
    WHERE kind IN (
        'serial_number',
        'system_uuid',
        'bios_uuid',
        'snmp_engine_id',
        'ssh_host_key_fingerprint'
    );

CREATE TABLE IF NOT EXISTS asset_addresses (
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    address_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    last_observation_id TEXT REFERENCES observations(observation_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, address_type, value)
);

CREATE INDEX IF NOT EXISTS idx_asset_addresses_lookup
    ON asset_addresses (site_id, address_type, value);

CREATE INDEX IF NOT EXISTS idx_asset_addresses_asset
    ON asset_addresses (asset_id, address_type, value);

CREATE TABLE IF NOT EXISTS sightings (
    sighting_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    observation_id TEXT NOT NULL REFERENCES observations(observation_id) ON DELETE CASCADE,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    node_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
    observation_type TEXT NOT NULL,
    observation_scope TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    source_protocol TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (observation_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_sightings_asset_observed_at
    ON sightings (asset_id, observed_at DESC, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sightings_site_observed_at
    ON sightings (site_id, observed_at DESC, created_at DESC);
