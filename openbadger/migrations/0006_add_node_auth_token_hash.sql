ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS auth_token_hash TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS nodes_auth_token_hash_unique
    ON nodes(auth_token_hash)
    WHERE auth_token_hash <> '';
