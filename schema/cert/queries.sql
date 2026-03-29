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
WITH upserted AS (
	INSERT INTO ${"schema"}.cert (
		name, subject, signer, cert, key, not_before, not_after, is_ca, enabled, tags, pv
	) VALUES (
		@name, @subject, @signer, @cert, @key, @not_before, @not_after, @is_ca, @enabled, @tags, @pv
	) ON CONFLICT (name) DO UPDATE SET
		subject = @subject,
		signer = @signer,
		cert = @cert,
		key = @key,
		not_before = @not_before,
		not_after = @not_after,
		is_ca = @is_ca,
		enabled = @enabled,
		tags = @tags,
		pv = @pv,
		ts = CURRENT_TIMESTAMP
	RETURNING
		name, subject, signer, cert, key, not_before, not_after, is_ca, enabled, tags, pv, ts
)
SELECT
	upserted.name,
	upserted.subject,
	upserted.signer,
	upserted.cert,
	upserted.key,
	upserted.not_before,
	upserted.not_after,
	upserted.is_ca,
	upserted.enabled,
	COALESCE(upserted.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, COALESCE(upserted.tags, '{}'::TEXT[])) AS effective_tags,
	upserted.pv,
	upserted.ts
FROM upserted
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.name, current.signer, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.name = upserted.name
		UNION ALL
		SELECT parent.name, parent.signer, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.signer = parent.name
	)
	SELECT COALESCE(array_agg(DISTINCT tag ORDER BY tag), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true;

-- cert.delete
WITH deleted AS (
	DELETE FROM ${"schema"}.cert WHERE
		name = @name
	RETURNING
		name, subject, signer, cert, key, not_before, not_after, is_ca, enabled, tags, pv, ts
)
SELECT
	deleted.name,
	deleted.subject,
	deleted.signer,
	deleted.cert,
	deleted.key,
	deleted.not_before,
	deleted.not_after,
	deleted.is_ca,
	deleted.enabled,
	COALESCE(deleted.tags, '{}'::TEXT[]) AS tags,
	COALESCE(deleted.tags, '{}'::TEXT[]) AS effective_tags,
	deleted.pv,
	deleted.ts
FROM deleted;

-- cert.select
SELECT
	cert_row.name,
	cert_row.subject,
	cert_row.signer,
	cert_row.cert,
	cert_row.key,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	cert_row.enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.pv,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.name, current.signer, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.name = cert_row.name
		UNION ALL
		SELECT parent.name, parent.signer, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.signer = parent.name
	)
	SELECT COALESCE(array_agg(DISTINCT tag ORDER BY tag), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
WHERE cert_row.name = @name;

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
	cert_row.enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.pv,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.name, current.signer, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.name = cert_row.name
		UNION ALL
		SELECT parent.name, parent.signer, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.signer = parent.name
	)
	SELECT COALESCE(array_agg(DISTINCT tag ORDER BY tag), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
${where}
${orderby}
