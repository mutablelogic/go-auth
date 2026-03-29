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
	"name" TEXT PRIMARY KEY,
	"subject" INTEGER NOT NULL REFERENCES ${"schema"}."subject"("id") ON DELETE CASCADE,
	"signer" TEXT REFERENCES ${"schema"}."cert"("name") ON DELETE RESTRICT,
	"not_before" TIMESTAMP NOT NULL,
	"not_after" TIMESTAMP NOT NULL,
	"is_ca" BOOLEAN NOT NULL,
	"enabled" BOOLEAN NOT NULL DEFAULT TRUE,
	"tags" TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
	"pv" INTEGER NOT NULL DEFAULT 0,
	"cert" BYTEA NOT NULL,
	"key" BYTEA NOT NULL,
	"ts" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- cert.cert.add_enabled
ALTER TABLE ${"schema"}."cert"
	ADD COLUMN IF NOT EXISTS "enabled" BOOLEAN NOT NULL DEFAULT TRUE;

-- cert.cert.add_tags
ALTER TABLE ${"schema"}."cert"
	ADD COLUMN IF NOT EXISTS "tags" TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

-- cert.cert.drop_root_index
DROP INDEX IF EXISTS ${"schema"}.cert_single_root_idx;

-- cert.cert.drop_root_requires_ca
ALTER TABLE ${"schema"}."cert"
	DROP CONSTRAINT IF EXISTS cert_root_requires_ca;

-- cert.cert.drop_non_root_has_signer
ALTER TABLE ${"schema"}."cert"
	DROP CONSTRAINT IF EXISTS cert_non_root_has_signer;

-- cert.cert.drop_validity_window
ALTER TABLE ${"schema"}."cert"
	DROP CONSTRAINT IF EXISTS cert_validity_window;

-- cert.cert.drop_pv_non_negative
ALTER TABLE ${"schema"}."cert"
	DROP CONSTRAINT IF EXISTS cert_pv_non_negative;

-- cert.cert.drop_is_root
ALTER TABLE ${"schema"}."cert"
	DROP COLUMN IF EXISTS "is_root";

-- cert.cert.add_root_requires_ca
ALTER TABLE ${"schema"}."cert"
	ADD CONSTRAINT cert_root_requires_ca CHECK ("name" <> CHR(36) || 'root' || CHR(36) OR ("is_ca" AND "signer" IS NULL));

-- cert.cert.add_non_root_has_signer
ALTER TABLE ${"schema"}."cert"
	ADD CONSTRAINT cert_non_root_has_signer CHECK ("name" = CHR(36) || 'root' || CHR(36) OR "signer" IS NOT NULL);

-- cert.cert.add_validity_window
ALTER TABLE ${"schema"}."cert"
	ADD CONSTRAINT cert_validity_window CHECK ("not_after" > "not_before");

-- cert.cert.add_pv_non_negative
ALTER TABLE ${"schema"}."cert"
	ADD CONSTRAINT cert_pv_non_negative CHECK ("pv" >= 0);
