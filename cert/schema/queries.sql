-- subject.insert
-- Inserts the subject, or returns an identical one, with the number of
-- certificates which use it
WITH existing AS (
	SELECT
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", (SELECT COUNT(*) FROM ${"schema"}."cert" WHERE "cert"."subject" = "subject"."id") AS "certs"
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
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", 0::BIGINT AS "certs"
)
SELECT * FROM inserted
UNION ALL
SELECT * FROM existing;

-- subject.update
-- Updates a subject which no certificate uses, as a certificate's subject is
-- in the certificate, which the row would no longer be
UPDATE ${"schema"}."subject" SET
	${patch}, "ts" = CURRENT_TIMESTAMP
WHERE
	"id" = @id AND NOT EXISTS (SELECT 1 FROM ${"schema"}."cert" WHERE "cert"."subject" = @id)
RETURNING
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", 0::BIGINT AS "certs";

-- subject.delete
-- Deletes a subject which no certificate uses, as deleting it would delete
-- its certificates
DELETE FROM ${"schema"}."subject" WHERE
	"id" = @id AND NOT EXISTS (SELECT 1 FROM ${"schema"}."cert" WHERE "cert"."subject" = @id)
RETURNING
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", 0::BIGINT AS "certs";

-- subject.select
SELECT
	"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", (SELECT COUNT(*) FROM ${"schema"}."cert" WHERE "cert"."subject" = "subject"."id") AS "certs"
FROM
	${"schema"}."subject"
WHERE
	"id" = @id;

-- subject.list
WITH q AS (
	SELECT
		"id", "organizationName", "organizationalUnit", "countryName", "localityName", "stateOrProvinceName", "streetAddress", "postalCode", "ts", (SELECT COUNT(*) FROM ${"schema"}."cert" WHERE "cert"."subject" = "subject"."id") AS "certs"
	FROM
		${"schema"}."subject"
	ORDER BY
		"id" ASC
)
SELECT * FROM q ${where};

-- cert.insert
WITH issuer_row AS (
	SELECT id
	FROM ${"schema"}.cert
	WHERE name = @issuer_name AND serial = @issuer_serial
), inserted AS (
	-- A certificate is never replaced: its name and serial are unique, so a
	-- second insert is a conflict, and a new row can only refer to rows
	-- which already exist, so issuers can't form a cycle
	INSERT INTO ${"schema"}.cert (
		name, serial, subject, issuer, cert, key, not_before, not_after, is_ca, enabled, tags, pv
	) VALUES (
		@name, @serial, @subject, (SELECT id FROM issuer_row), @cert, @key, @not_before, @not_after, @is_ca, @enabled, @tags, @pv
	)
	RETURNING
		id, name, serial, subject, issuer, cert, not_before, not_after, is_ca, enabled, tags, ts
)
SELECT
	inserted.id,
	inserted.name,
	inserted.serial,
	inserted.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	inserted.cert,
	inserted.not_before,
	inserted.not_after,
	inserted.is_ca,
	COALESCE(effective.effective_enabled, inserted.enabled) AS enabled,
	COALESCE(inserted.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, COALESCE(inserted.tags, '{}'::TEXT[])) AS effective_tags,
	inserted.ts
FROM inserted
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = inserted.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = inserted.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT inserted.id, inserted.issuer, inserted.enabled, COALESCE(inserted.tags, '{}'::TEXT[]) AS tags
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true;

-- cert.delete
WITH deleted AS (
	DELETE FROM ${"schema"}.cert WHERE
		name = @name AND serial = @serial
	RETURNING
		id, name, serial, subject, issuer, cert, not_before, not_after, is_ca, enabled, tags, ts
)
SELECT
	deleted.id,
	deleted.name,
	deleted.serial,
	deleted.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	deleted.cert,
	deleted.not_before,
	deleted.not_after,
	deleted.is_ca,
	COALESCE(effective.effective_enabled, deleted.enabled) AS enabled,
	COALESCE(deleted.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, COALESCE(deleted.tags, '{}'::TEXT[])) AS effective_tags,
	deleted.ts
FROM deleted
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = deleted.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = deleted.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT deleted.id, deleted.issuer, deleted.enabled, COALESCE(deleted.tags, '{}'::TEXT[]) AS tags
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true;

-- cert.update
WITH updated AS (
	UPDATE ${"schema"}.cert SET
		${patch},
		"ts" = CURRENT_TIMESTAMP
	WHERE
		"name" = @name AND "serial" = @serial
	RETURNING
		id, name, serial, subject, issuer, cert, not_before, not_after, is_ca, enabled, tags, ts
)
SELECT
	updated.id,
	updated.name,
	updated.serial,
	updated.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	updated.cert,
	updated.not_before,
	updated.not_after,
	updated.is_ca,
	COALESCE(effective.effective_enabled, updated.enabled) AS enabled,
	COALESCE(updated.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, COALESCE(updated.tags, '{}'::TEXT[])) AS effective_tags,
	updated.ts
FROM updated
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = updated.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = updated.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT updated.id, updated.issuer, updated.enabled, COALESCE(updated.tags, '{}'::TEXT[]) AS tags
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true;

-- cert.select
SELECT
	cert_row.id,
	cert_row.name,
	cert_row.serial,
	cert_row.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	cert_row.cert,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	COALESCE(effective.effective_enabled, cert_row.enabled) AS enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = cert_row.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = cert_row.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = cert_row.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
WHERE cert_row.name = @name AND cert_row.serial = @serial;

-- cert.select_latest
SELECT
	cert_row.id,
	cert_row.name,
	cert_row.serial,
	cert_row.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	cert_row.cert,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	COALESCE(effective.effective_enabled, cert_row.enabled) AS enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = cert_row.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = cert_row.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = cert_row.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
WHERE cert_row.id = (
	SELECT selected.id
	FROM ${"schema"}.cert AS selected
	WHERE selected.name = @name
	ORDER BY selected.id DESC
	LIMIT 1
);

-- cert.chain
WITH RECURSIVE chain AS (
	SELECT
		current.id,
		current.name,
		current.serial,
		current.subject,
		current.issuer,
		current.cert,
		current.not_before,
		current.not_after,
		current.is_ca,
		current.enabled,
		COALESCE(current.tags, '{}'::TEXT[]) AS tags,
		current.ts,
		0 AS depth
	FROM ${"schema"}.cert AS current
	WHERE current.name = @name AND current.serial = @serial
	UNION ALL
	SELECT
		parent.id,
		parent.name,
		parent.serial,
		parent.subject,
		parent.issuer,
		parent.cert,
		parent.not_before,
		parent.not_after,
		parent.is_ca,
		parent.enabled,
		COALESCE(parent.tags, '{}'::TEXT[]) AS tags,
		parent.ts,
		chain.depth + 1 AS depth
	FROM ${"schema"}.cert AS parent
	JOIN chain ON chain.issuer = parent.id
)
SELECT
	chain.id,
	chain.name,
	chain.serial,
	chain.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	chain.cert,
	chain.not_before,
	chain.not_after,
	chain.is_ca,
	COALESCE(effective.effective_enabled, chain.enabled) AS enabled,
	COALESCE(chain.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	chain.ts
FROM chain
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = chain.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = chain.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE effective_chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = chain.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN effective_chain ON effective_chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(effective_chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM effective_chain
	LEFT JOIN LATERAL unnest(effective_chain.tags) AS tag ON true
) AS effective ON true
ORDER BY chain.depth ASC;

-- cert.list
SELECT
	cert_row.id,
	cert_row.name,
	cert_row.serial,
	cert_row.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	cert_row.cert,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	COALESCE(effective.effective_enabled, cert_row.enabled) AS enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = cert_row.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = cert_row.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = cert_row.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
${where}
${orderby}

-- cert.select_private
SELECT
	cert_row.id,
	cert_row.name,
	cert_row.serial,
	cert_row.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	cert_row.cert,
	cert_row.key,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	COALESCE(effective.effective_enabled, cert_row.enabled) AS enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.pv,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = cert_row.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = cert_row.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = cert_row.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
WHERE cert_row.name = @name AND cert_row.serial = @serial;

-- cert.select_latest_private
SELECT
	cert_row.id,
	cert_row.name,
	cert_row.serial,
	cert_row.subject,
	subject_row."organizationName",
	subject_row."organizationalUnit",
	subject_row."countryName",
	subject_row."localityName",
	subject_row."stateOrProvinceName",
	subject_row."streetAddress",
	subject_row."postalCode",
	subject_row."ts",
	issuer.name AS signer_name,
	issuer.serial AS signer_serial,
	cert_row.cert,
	cert_row.key,
	cert_row.not_before,
	cert_row.not_after,
	cert_row.is_ca,
	COALESCE(effective.effective_enabled, cert_row.enabled) AS enabled,
	COALESCE(cert_row.tags, '{}'::TEXT[]) AS tags,
	COALESCE(effective.effective_tags, '{}'::TEXT[]) AS effective_tags,
	cert_row.pv,
	cert_row.ts
FROM ${"schema"}.cert AS cert_row
LEFT JOIN ${"schema"}.subject AS subject_row ON subject_row.id = cert_row.subject
LEFT JOIN ${"schema"}.cert AS issuer ON issuer.id = cert_row.issuer
LEFT JOIN LATERAL (
	WITH RECURSIVE chain AS (
		SELECT current.id, current.issuer, current.enabled, COALESCE(current.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS current
		WHERE current.id = cert_row.id
		UNION ALL
		SELECT parent.id, parent.issuer, parent.enabled, COALESCE(parent.tags, '{}'::TEXT[]) AS tags
		FROM ${"schema"}.cert AS parent
		JOIN chain ON chain.issuer = parent.id
	)
	SELECT
		COALESCE(bool_and(chain.enabled), TRUE) AS effective_enabled,
		COALESCE(array_agg(DISTINCT tag ORDER BY tag) FILTER (WHERE tag IS NOT NULL), '{}'::TEXT[]) AS effective_tags
	FROM chain
	LEFT JOIN LATERAL unnest(chain.tags) AS tag ON true
) AS effective ON true
WHERE cert_row.id = (
	SELECT selected.id
	FROM ${"schema"}.cert AS selected
	WHERE selected.name = @name
	ORDER BY selected.id DESC
	LIMIT 1
);
