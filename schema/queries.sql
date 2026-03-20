-- user.insert
WITH inserted AS (
    INSERT INTO ${"schema"}.user (name, email, meta, status, expires_at)
      VALUES (@name, @email, @meta, @status, @expires_at)
      RETURNING id, name, email, meta, status, created_at, expires_at, modified_at
) SELECT
    inserted.*,
    COALESCE(identity_claims.claims, '{}'::jsonb) AS claims,
    COALESCE(group_memberships.groups, '{}'::text[]) AS groups,
    COALESCE(group_memberships.scopes, '{}'::text[]) AS scopes
FROM inserted LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = inserted.id
) AS identity_claims ON true
LEFT JOIN LATERAL (
    SELECT
    array_agg(DISTINCT group_row.id ORDER BY group_row.id) AS groups,
        array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope IS NOT NULL) AS scopes
    FROM ${"schema"}.user_group AS user_group
    JOIN ${"schema"}."group" AS group_row ON group_row.id = user_group."group"
    LEFT JOIN LATERAL unnest(group_row.scopes) AS scope ON true
    WHERE user_group."user" = inserted.id
      AND group_row.enabled
) AS group_memberships ON true;

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
    COALESCE(group_memberships.groups, '{}'::text[]) AS groups,
    COALESCE(group_memberships.scopes, '{}'::text[]) AS scopes
FROM ${"schema"}.user AS user_row
LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = user_row.id
) AS identity_claims ON true
LEFT JOIN LATERAL (
    SELECT
    array_agg(DISTINCT group_row.id ORDER BY group_row.id) AS groups,
        array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope IS NOT NULL) AS scopes
    FROM ${"schema"}.user_group AS user_group
    JOIN ${"schema"}."group" AS group_row ON group_row.id = user_group."group"
    LEFT JOIN LATERAL unnest(group_row.scopes) AS scope ON true
    WHERE user_group."user" = user_row.id
      AND group_row.enabled
) AS group_memberships ON true
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
    COALESCE(group_memberships.groups, '{}'::text[]) AS groups,
    COALESCE(group_memberships.scopes, '{}'::text[]) AS scopes
FROM updated
LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = updated.id
) AS identity_claims ON true
LEFT JOIN LATERAL (
    SELECT
    array_agg(DISTINCT group_row.id ORDER BY group_row.id) AS groups,
        array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope IS NOT NULL) AS scopes
    FROM ${"schema"}.user_group AS user_group
    JOIN ${"schema"}."group" AS group_row ON group_row.id = user_group."group"
    LEFT JOIN LATERAL unnest(group_row.scopes) AS scope ON true
    WHERE user_group."user" = updated.id
      AND group_row.enabled
) AS group_memberships ON true;

-- user.delete
WITH deleted_claims AS (
    SELECT
        identity."user" AS id,
        jsonb_object_agg(claim.key, claim.value) AS claims
    FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
    WHERE identity."user" = @id
    GROUP BY identity."user"
  ), deleted_groups AS (
    SELECT
          user_group."user" AS id,
          array_agg(DISTINCT group_row.id ORDER BY group_row.id) AS groups,
          array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope IS NOT NULL) AS scopes
    FROM ${"schema"}.user_group AS user_group
    JOIN ${"schema"}."group" AS group_row ON group_row.id = user_group."group"
    LEFT JOIN LATERAL unnest(group_row.scopes) AS scope ON true
    WHERE user_group."user" = @id
      AND group_row.enabled
    GROUP BY user_group."user"
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
    COALESCE(deleted_groups.groups, '{}'::text[]) AS groups,
    COALESCE(deleted_groups.scopes, '{}'::text[]) AS scopes
FROM deleted
LEFT JOIN deleted_claims ON deleted_claims.id = deleted.id
LEFT JOIN deleted_groups ON deleted_groups.id = deleted.id;

-- user.list
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
    COALESCE(group_memberships.groups, '{}'::text[]) AS groups,
    COALESCE(group_memberships.scopes, '{}'::text[]) AS scopes
FROM ${"schema"}.user AS user_row
LEFT JOIN LATERAL (
    SELECT jsonb_object_agg(claim.key, claim.value) AS claims
      FROM ${"schema"}.identity
    CROSS JOIN LATERAL jsonb_each(identity.claims) AS claim(key, value)
      WHERE identity."user" = user_row.id
) AS identity_claims ON true
LEFT JOIN LATERAL (
    SELECT
    array_agg(DISTINCT group_row.id ORDER BY group_row.id) AS groups,
        array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope IS NOT NULL) AS scopes
    FROM ${"schema"}.user_group AS user_group
    JOIN ${"schema"}."group" AS group_row ON group_row.id = user_group."group"
    LEFT JOIN LATERAL unnest(group_row.scopes) AS scope ON true
    WHERE user_group."user" = user_row.id
      AND group_row.enabled
) AS group_memberships ON true
${where}
${orderby}

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

-- identity.list
SELECT
    identity."user",
    identity.provider,
    identity.sub,
    identity.email,
    identity.claims,
    identity.created_at,
    identity.modified_at
FROM ${"schema"}.identity AS identity
${where}
${orderby}

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

-- session.insert
INSERT INTO ${"schema"}.session ("user", expires_at)
  VALUES (@user, NOW() + @expires_in)
  RETURNING id, "user", expires_at, created_at, revoked_at;

-- session.select
SELECT
    session.id,
    session."user",
    session.expires_at,
    session.created_at,
    session.revoked_at
FROM ${"schema"}.session AS session
WHERE session.id = @id;

-- session.update
UPDATE ${"schema"}.session
SET ${patch}
WHERE id = @id
RETURNING id, "user", expires_at, created_at, revoked_at;

-- session.refresh
UPDATE ${"schema"}.session AS session
SET expires_at = NOW() + @expires_in
FROM ${"schema"}.user AS user_row
WHERE session.id = @id
  AND session."user" = user_row.id
  AND session.revoked_at IS NULL
  AND session.expires_at > NOW()
  AND (user_row.expires_at IS NULL OR user_row.expires_at > NOW())
  AND (user_row.status IS NULL OR user_row.status = 'active')
RETURNING session.id, session."user", session.expires_at, session.created_at, session.revoked_at;

-- session.revoke
UPDATE ${"schema"}.session
SET revoked_at = NOW()
WHERE id = @id
RETURNING id, "user", expires_at, created_at, revoked_at;

-- session.cleanup
WITH candidates AS (
  SELECT session.id
  FROM ${"schema"}.session AS session
  WHERE session.revoked_at IS NOT NULL
     OR session.expires_at < NOW()
  ORDER BY session.created_at ASC, session.id ASC
  LIMIT @cleanup_limit
), deleted AS (
  DELETE FROM ${"schema"}.session AS session
  USING candidates
  WHERE session.id = candidates.id
  RETURNING session.id, session."user", session.expires_at, session.created_at, session.revoked_at
)
SELECT id, "user", expires_at, created_at, revoked_at
FROM deleted
ORDER BY created_at ASC, id ASC;

-- session.delete
DELETE FROM ${"schema"}.session
WHERE id = @id
RETURNING id, "user", expires_at, created_at, revoked_at;

-- group.insert
INSERT INTO ${"schema"}."group" (id, description, enabled, scopes, meta)
  VALUES (@id, @description, @enabled, @scopes, @meta)
  RETURNING id, description, enabled, scopes, meta;

-- group.select
SELECT
    group_row.id,
    group_row.description,
    group_row.enabled,
    group_row.scopes,
    group_row.meta
FROM ${"schema"}."group" AS group_row
WHERE group_row.id = @id;

-- group.update
UPDATE ${"schema"}."group"
SET ${patch}
WHERE id = @id
RETURNING id, description, enabled, scopes, meta;

-- group.delete
DELETE FROM ${"schema"}."group"
WHERE id = @id
RETURNING id, description, enabled, scopes, meta;

-- group.list
SELECT
    group_row.id,
    group_row.description,
    group_row.enabled,
    group_row.scopes,
    group_row.meta
FROM ${"schema"}."group" AS group_row
${where}
${orderby}
