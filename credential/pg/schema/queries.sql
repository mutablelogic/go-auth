
-- credential.list
SELECT
	"key", "description", "pv", "updated_at"
FROM
	${"schema"}."credential"
${where}
ORDER BY
	"key"

-- credential.get
SELECT
	"key", "pv", "credential"
FROM
	${"schema"}."credential"
WHERE
	"key" = @key

-- credential.get_meta
-- The key and the time it was stored, without the encrypted credential
SELECT
	"key", "description", "pv", "updated_at"
FROM
	${"schema"}."credential"
WHERE
	"key" = @key

-- credential.get_pv
SELECT
	"key", "credential"
FROM
	${"schema"}."credential"
WHERE
	"key" = @key
AND
	"pv" = CAST(@pv AS INT)

-- credential.delete
DELETE FROM ${"schema"}."credential"
WHERE
	"key" = @key
RETURNING
	"key", "description", "pv", "updated_at"

-- credential.upsert
INSERT INTO ${"schema"}."credential" (
	"key", "pv", "credential"
)
VALUES (
	@key, CAST(@pv AS INT), @credentials
)
ON CONFLICT ("key") DO UPDATE
SET
	"pv" = EXCLUDED."pv",
	"credential" = EXCLUDED."credential",
	"updated_at" = now()
RETURNING
	"key", "description", "pv", "updated_at"

-- credential.rotate
UPDATE ${"schema"}."credential"
SET
	"pv" = CAST(@pv AS INT),
	"credential" = @credentials,
	"updated_at" = now()
WHERE
	"key" = @key
AND
	"pv" = CAST(@oldpv AS INT)
AND
	"credential" = @oldcredentials
RETURNING
	"key", "description", "pv", "updated_at"

-- credential.describe
-- The credential's description, or none, when it's empty, which doesn't
-- change when it was updated, as its value is the same
UPDATE ${"schema"}."credential"
SET
	"description" = NULLIF(@description, '')
WHERE
	"key" = @key
RETURNING
	"key", "description", "pv", "updated_at"
