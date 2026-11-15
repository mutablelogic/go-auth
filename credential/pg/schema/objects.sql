
-- credential
CREATE TABLE IF NOT EXISTS ${"schema"}."credential" (
  "key"                TEXT NOT NULL,
  "pv"                 INT NOT NULL DEFAULT 0,
  "credential"         BYTEA NOT NULL,
  "updated_at"         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY ("key"),
  CHECK ("key" ~ '^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$') -- matches types.ReIdentifier
);
