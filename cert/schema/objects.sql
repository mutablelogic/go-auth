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
	"ts" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- cert.cert.name_serial_index
CREATE UNIQUE INDEX IF NOT EXISTS cert_name_serial_idx ON ${"schema"}."cert" ("name", "serial");

-- cert.cert.name_index
CREATE INDEX IF NOT EXISTS cert_name_idx ON ${"schema"}."cert" ("name");

-- cert.cert.issuer_index
CREATE INDEX IF NOT EXISTS cert_issuer_idx ON ${"schema"}."cert" ("issuer");
