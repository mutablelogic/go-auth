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
	"is_root" BOOLEAN NOT NULL DEFAULT FALSE,
	"pv" INTEGER NOT NULL DEFAULT 0,
	"cert" BYTEA NOT NULL,
	"key" BYTEA NOT NULL,
	"ts" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT cert_root_requires_ca CHECK (NOT "is_root" OR ("is_ca" AND "signer" IS NULL)),
	CONSTRAINT cert_validity_window CHECK ("not_after" > "not_before"),
	CONSTRAINT cert_non_root_has_signer CHECK ("is_root" OR "signer" IS NOT NULL),
	CONSTRAINT cert_pv_non_negative CHECK ("pv" >= 0)
);

-- cert.cert.root_index
CREATE UNIQUE INDEX IF NOT EXISTS cert_single_root_idx
	ON ${"schema"}."cert" ("is_root")
	WHERE "is_root";
