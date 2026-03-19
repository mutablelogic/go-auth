-- auth.user_status
DO $$ BEGIN
  CREATE TYPE ${"schema"}.USER_STATUS AS ENUM ('new', 'active', 'inactive', 'suspended', 'deleted');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- auth.user
CREATE TABLE IF NOT EXISTS ${"schema"}.user (
    "id"          UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "name"        TEXT NOT NULL DEFAULT '',
    "email"       TEXT NOT NULL DEFAULT '',
    "meta"        JSONB NOT NULL DEFAULT '{}',
    "status"      ${"schema"}.USER_STATUS,
    "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    "expires_at"  TIMESTAMPTZ NULL,
  "modified_at" TIMESTAMPTZ NULL
);

UPDATE ${"schema"}.user
SET "email" = LOWER(TRIM("email"))
WHERE "email" IS DISTINCT FROM LOWER(TRIM("email"));

CREATE UNIQUE INDEX IF NOT EXISTS user_email_key
ON ${"schema"}.user ("email")
WHERE "email" <> '';

-- auth.identity
CREATE TABLE IF NOT EXISTS ${"schema"}.identity (
    "user"        UUID        NOT NULL REFERENCES ${"schema"}.user (id) ON DELETE CASCADE,
    "provider"    TEXT        NOT NULL,
    "sub"         TEXT        NOT NULL,
    "email"       TEXT        NOT NULL DEFAULT '',
    "claims"      JSONB       NOT NULL DEFAULT '{}',
    "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    "modified_at" TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_pkey PRIMARY KEY ("provider", "sub")
);
