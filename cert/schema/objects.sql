-- cert.subject
CREATE TABLE IF NOT EXISTS ${"schema"}."subject" (
	"id" SERIAL PRIMARY KEY,
	"organizationName" TEXT,
	"organizationalUnit" TEXT,
	"countryName" TEXT,
	"localityName" TEXT,
	"stateOrProvinceName" TEXT,
	"streetAddress" TEXT,
	"postalCode" TEXT,
	"ts" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- cert.cert
CREATE TABLE IF NOT EXISTS ${"schema"}."cert" (
	"id" BIGSERIAL PRIMARY KEY,
	"name" TEXT NOT NULL,
	"serial" TEXT NOT NULL,
	"subject" INTEGER NOT NULL REFERENCES ${"schema"}."subject"("id") ON DELETE CASCADE,
	"issuer" BIGINT REFERENCES ${"schema"}."cert"("id") ON DELETE RESTRICT,
	"not_before" TIMESTAMP NOT NULL,
	"not_after" TIMESTAMP NOT NULL,
	"is_ca" BOOLEAN NOT NULL,
	"enabled" BOOLEAN NOT NULL DEFAULT TRUE,
	"tags" TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
	"pv" INTEGER NOT NULL DEFAULT 0,
	"cert" BYTEA NOT NULL,
	"key" BYTEA NOT NULL,
	"ts" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	-- Only the root certificate has no issuer, so a certificate whose signer
	-- isn't stored can't be inserted. The root name is
	-- written with CHR(36), as queries expand names after a dollar sign
	CONSTRAINT cert_issuer_check CHECK (("name" = CHR(36) || 'root' || CHR(36)) = ("issuer" IS NULL))
);

-- cert.cert.name_serial_index
CREATE UNIQUE INDEX IF NOT EXISTS cert_name_serial_idx ON ${"schema"}."cert" ("name", "serial");

-- cert.cert.name_index
CREATE INDEX IF NOT EXISTS cert_name_idx ON ${"schema"}."cert" ("name");

-- cert.cert.issuer_index
CREATE INDEX IF NOT EXISTS cert_issuer_idx ON ${"schema"}."cert" ("issuer");

-- cert.notify_cert_func
-- Notifies the channel of a change of a certificate, as JSON, which go-pg's
-- pgbroadcaster publishes, by its name, without its keys
CREATE OR REPLACE FUNCTION ${"schema"}.cert_notify() RETURNS TRIGGER AS $$
DECLARE
    v_name TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_name := OLD."name";
    ELSE
        v_name := NEW."name";
    END IF;
    PERFORM pg_notify(${'channel'}, json_build_object(
        'action', CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update' ELSE 'delete' END,
        'schema', ${'schema'},
        'table', 'cert',
        'row', v_name
    )::TEXT);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- cert.notify_cert_trigger
CREATE OR REPLACE TRIGGER cert_notify_trigger
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}."cert"
    FOR EACH ROW EXECUTE FUNCTION ${"schema"}.cert_notify();

-- cert.notify_subject_func
-- Notifies the channel that certificates changed, without which ones, when
-- subjects are updated, as a subject can be any number of certificates'. A
-- new subject isn't any certificate's yet, and deleting one deletes its
-- certificates, which notify of themselves.
CREATE OR REPLACE FUNCTION ${"schema"}.cert_subject_notify() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify(${'channel'}, json_build_object(
        'action', 'update',
        'schema', ${'schema'},
        'table', 'cert'
    )::TEXT);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- cert.notify_subject_trigger
CREATE OR REPLACE TRIGGER cert_subject_notify_trigger
    AFTER UPDATE ON ${"schema"}."subject"
    FOR EACH STATEMENT EXECUTE FUNCTION ${"schema"}.cert_subject_notify();
