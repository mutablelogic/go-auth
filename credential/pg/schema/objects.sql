
-- credential
CREATE TABLE IF NOT EXISTS ${"schema"}."credential" (
  "key"                TEXT NOT NULL,
  "pv"                 INT NOT NULL DEFAULT 0,
  "credential"         BYTEA NOT NULL,
  "description"        TEXT,
  "updated_at"         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY ("key"),
  CHECK ("key" ~ '^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$') -- matches types.ReIdentifier
);

-- credential.description
-- A credential's description, for a table which was created without it
ALTER TABLE ${"schema"}."credential" ADD COLUMN IF NOT EXISTS "description" TEXT;
