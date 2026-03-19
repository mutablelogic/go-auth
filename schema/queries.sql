-- user.insert
WITH inserted AS (
    INSERT INTO ${"schema"}.user (name, email, meta, status, expires_at)
      VALUES (@name, @email, @meta, @status, @expires_at)
      RETURNING id, name, email, meta, status, created_at, expires_at, modified_at
) SELECT
    inserted.*,
    COALESCE(identity_claims.claims, '{}'::jsonb) AS claims,
    '{}'::text[] AS groups,
    '{}'::text[] AS scopes
FROM inserted LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = inserted.id
) AS identity_claims ON true;

-- user.select
SELECT
    user_row.id,
    user_row.name,
    user_row.email,
    user_row.meta,
    user_row.status,
    user_row.created_at,
    user_row.expires_at,
    user_row.modified_at,
    COALESCE(identity_claims.claims, '{}'::jsonb) AS claims,
    '{}'::text[] AS groups,
    '{}'::text[] AS scopes
FROM ${"schema"}.user AS user_row
LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = user_row.id
) AS identity_claims ON true
WHERE user_row.id = @id;

-- user.update
WITH updated AS (
    UPDATE ${"schema"}.user
  SET modified_at = NOW(), ${patch}
    WHERE id = @id
    RETURNING id, name, email, meta, status, created_at, expires_at, modified_at
)
SELECT
    updated.id,
    updated.name,
    updated.email,
    updated.meta,
    updated.status,
    updated.created_at,
    updated.expires_at,
    updated.modified_at,
    COALESCE(identity_claims.claims, '{}'::jsonb) AS claims,
    '{}'::text[] AS groups,
    '{}'::text[] AS scopes
FROM updated
LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = updated.id
) AS identity_claims ON true;

-- user.delete
WITH deleted_claims AS (
    SELECT
        identity."user" AS id,
        jsonb_object_agg(claim.key, claim.value) AS claims
    FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
    WHERE identity."user" = @id
    GROUP BY identity."user"
), deleted AS (
    DELETE FROM ${"schema"}.user
    WHERE id = @id
    RETURNING id, name, email, meta, status, created_at, expires_at, modified_at
)
SELECT
    deleted.id,
    deleted.name,
    deleted.email,
    deleted.meta,
    deleted.status,
    deleted.created_at,
    deleted.expires_at,
    deleted.modified_at,
    COALESCE(deleted_claims.claims, '{}'::jsonb) AS claims,
    '{}'::text[] AS groups,
    '{}'::text[] AS scopes
FROM deleted
LEFT JOIN deleted_claims ON deleted_claims.id = deleted.id;

-- identity.insert
INSERT INTO ${"schema"}.identity ("user", provider, sub, email, claims)
  VALUES (@user, @provider, @sub, @email, @claims)
  RETURNING "user", provider, sub, email, claims, created_at, modified_at;

-- identity.select
SELECT
    identity."user",
    identity.provider,
    identity.sub,
    identity.email,
    identity.claims,
    identity.created_at,
    identity.modified_at
FROM ${"schema"}.identity AS identity
WHERE identity.provider = @provider
  AND identity.sub = @sub;

-- identity.update
UPDATE ${"schema"}.identity
SET modified_at = NOW(), ${patch}
WHERE provider = @provider
  AND sub = @sub
RETURNING "user", provider, sub, email, claims, created_at, modified_at;

-- identity.delete
DELETE FROM ${"schema"}.identity
WHERE provider = @provider
  AND sub = @sub
RETURNING "user", provider, sub, email, claims, created_at, modified_at;
