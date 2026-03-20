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
    "modified_at" TIMESTAMPTZ NULL,
    CONSTRAINT user_email_key UNIQUE ("email")
);

-- auth.identity
CREATE TABLE IF NOT EXISTS ${"schema"}.identity (
    "user"        UUID        NOT NULL REFERENCES ${"schema"}."user" (id) ON DELETE CASCADE,
    "provider"    TEXT        NOT NULL,
    "sub"         TEXT        NOT NULL,
    "email"       TEXT        NOT NULL DEFAULT '',
    "claims"      JSONB       NOT NULL DEFAULT '{}',
    "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    "modified_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identity_pkey PRIMARY KEY ("provider", "sub")
);

-- auth.session
CREATE TABLE IF NOT EXISTS ${"schema"}.session (
    "id"            UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "user"          UUID        NOT NULL REFERENCES ${"schema"}."user" (id) ON DELETE CASCADE,
    "expires_at"    TIMESTAMPTZ NOT NULL,
    "created_at"    TIMESTAMPTZ NOT NULL DEFAULT now(),
    "revoked_at"    TIMESTAMPTZ NULL
);

-- auth.session.user_index
CREATE INDEX IF NOT EXISTS session_user_idx ON ${"schema"}.session ("user");

-- auth.group
CREATE TABLE IF NOT EXISTS ${"schema"}.group (
    "id"          TEXT    NOT NULL PRIMARY KEY CONSTRAINT groups_name_identifier CHECK (id ~ '^[a-zA-Z][a-zA-Z0-9_-]{0,63}$'),
    "description" TEXT    NULL,
    "enabled"     BOOLEAN NOT NULL DEFAULT true,
    "scopes"      TEXT[]  NOT NULL DEFAULT '{}',
    "meta"        JSONB   NOT NULL DEFAULT '{}'
);

-- auth.user_group
CREATE TABLE IF NOT EXISTS ${"schema"}.user_group (
    "user"  UUID   NOT NULL REFERENCES ${"schema"}.user  (id)   ON DELETE CASCADE,
    "group" TEXT   NOT NULL REFERENCES ${"schema"}.group (id) ON DELETE CASCADE,
    CONSTRAINT user_group_pkey PRIMARY KEY ("user", "group")
);
