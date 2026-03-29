-- subject.insert
WITH existing AS (
	SELECT
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts"
	FROM
		${"schema"}."subject"
	WHERE
		"organizationName" IS NOT DISTINCT FROM @organizationName AND
		"organizationalUnit" IS NOT DISTINCT FROM @organizationalUnit AND
		"countryName" IS NOT DISTINCT FROM @countryName AND
		"localityName" IS NOT DISTINCT FROM @localityName AND
		"stateOrProvinceName" IS NOT DISTINCT FROM @stateOrProvinceName AND
		"streetAddress" IS NOT DISTINCT FROM @streetAddress AND
		"postalCode" IS NOT DISTINCT FROM @postalCode
	LIMIT 1
), inserted AS (
	INSERT INTO ${"schema"}."subject" (
		"organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode"
	)
	SELECT
		@organizationName, @organizationalUnit, @countryName, @localityName, @stateOrProvinceName, @streetAddress, @postalCode
	WHERE
		NOT EXISTS (SELECT 1 FROM existing)
	RETURNING
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts"
)
SELECT * FROM inserted
UNION ALL
SELECT * FROM existing;

-- subject.update
UPDATE ${"schema"}."subject" SET
	${patch}, "ts" = CURRENT_TIMESTAMP
WHERE
	"id" = @id
RETURNING
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts";

-- subject.delete
DELETE FROM ${"schema"}."subject" WHERE
	"id" = @id
RETURNING
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts";

-- subject.select
SELECT
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts"
FROM
	${"schema"}."subject"
WHERE
	"id" = @id;

-- subject.list
WITH q AS (
	SELECT
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts"
	FROM
		${"schema"}."subject"
)
SELECT * FROM q ${where};

-- cert.insert
INSERT INTO ${"schema"}.cert (
	name, subject, signer, cert, key, not_before, not_after, is_ca, is_root, pv
) VALUES (
	@name, @subject, @signer, @cert, @key, @not_before, @not_after, @is_ca, @is_root, @pv
) ON CONFLICT (name) DO UPDATE SET
	subject = @subject,
	signer = @signer,
	cert = @cert,
	key = @key,
	not_before = @not_before,
	not_after = @not_after,
	is_ca = @is_ca,
	is_root = @is_root,
	pv = @pv,
	ts = CURRENT_TIMESTAMP
RETURNING
	name, subject, signer, cert, key, not_before, not_after, is_ca, is_root, pv, ts;

-- cert.delete
DELETE FROM ${"schema"}.cert WHERE
	name = @name
RETURNING
	name, subject, signer, cert, key, not_before, not_after, is_ca, is_root, pv, ts;

-- cert.select
SELECT
	name, subject, signer, cert, key, not_before, not_after, is_ca, is_root, pv, ts
FROM ${"schema"}.cert
WHERE name = @name;

-- cert.list
SELECT
	cert_row.name,
	cert_row.subject,
	cert_row.signer,
	cert_row.cert,
	cert_row.key,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	cert_row.is_root,
	cert_row.pv,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
${where}
${orderby}
