
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

-- credential.notify_func
-- Notifies the channel of a change of a credential, as JSON, which go-pg's
-- pgbroadcaster publishes, by its key, without its value
CREATE OR REPLACE FUNCTION ${"schema"}.credential_notify() RETURNS TRIGGER AS $$
DECLARE
    v_key TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_key := OLD."key";
    ELSE
        v_key := NEW."key";
    END IF;
    PERFORM pg_notify(${'channel'}, json_build_object(
        'action', CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update' ELSE 'delete' END,
        'schema', ${'schema'},
        'table', 'credential',
        'row', v_key
    )::TEXT);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- credential.notify_trigger
CREATE OR REPLACE TRIGGER credential_notify_trigger
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}."credential"
    FOR EACH ROW EXECUTE FUNCTION ${"schema"}.credential_notify();
