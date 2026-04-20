-- auth.extension.pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

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
    "refresh_expires_at" TIMESTAMPTZ NOT NULL,
    "refresh_counter" BIGINT      NOT NULL DEFAULT 0,
    "created_at"    TIMESTAMPTZ NOT NULL DEFAULT now(),
    "revoked_at"    TIMESTAMPTZ NULL
);

-- auth.session.user_index
CREATE INDEX IF NOT EXISTS session_user_idx ON ${"schema"}.session ("user");

-- auth.apikey
CREATE TABLE IF NOT EXISTS ${"schema"}.apikey (
    "id"          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "hash"        BYTEA       NOT NULL CONSTRAINT apikey_hash_key UNIQUE,
    "user"        UUID        NOT NULL REFERENCES ${"schema"}."user" (id) ON DELETE CASCADE,
    "name"        TEXT        NOT NULL,
    "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    "modified_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "expires_at"  TIMESTAMPTZ NULL
);

-- auth.apikey.user_index
CREATE INDEX IF NOT EXISTS apikey_user_idx ON ${"schema"}.apikey ("user");

-- auth.apikey.user_name_unique_index
CREATE UNIQUE INDEX IF NOT EXISTS apikey_user_name_idx ON ${"schema"}.apikey ("user", "name");

-- auth.group
CREATE TABLE IF NOT EXISTS ${"schema"}.group (
    "id"          TEXT    NOT NULL PRIMARY KEY CONSTRAINT groups_name_identifier CHECK (id ~ '^([a-zA-Z][a-zA-Z0-9_-]{0,63}|\$[a-zA-Z][a-zA-Z0-9_]*\$)$'),
    "description" TEXT    NULL,
    "enabled"     BOOLEAN NOT NULL DEFAULT true,
    "scopes"      TEXT[]  NOT NULL DEFAULT '{}',
    "meta"        JSONB   NOT NULL DEFAULT '{}'
);

-- auth.group.constraint
DO $$ BEGIN
    ALTER TABLE ${"schema"}."group" DROP CONSTRAINT IF EXISTS groups_name_identifier;
    INSERT INTO ${"schema"}."group" (id, description, enabled, scopes, meta)
    VALUES (
        ${'system_group'},
        'Server-managed group. Members have full access to the management API and CLI.',
        true,
        '{}'::text[],
        '{}'::jsonb
    )
    ON CONFLICT (id) DO NOTHING;
    ALTER TABLE ${"schema"}."group" ADD CONSTRAINT groups_name_identifier
        CHECK (id ~ '^([a-zA-Z][a-zA-Z0-9_-]{0,63}|\$[a-zA-Z][a-zA-Z0-9_]*\$)$');
END $$;

-- auth.user_group
CREATE TABLE IF NOT EXISTS ${"schema"}.user_group (
    "user"  UUID   NOT NULL REFERENCES ${"schema"}.user  (id)   ON DELETE CASCADE,
    "group" TEXT   NOT NULL REFERENCES ${"schema"}.group (id) ON DELETE CASCADE,
    CONSTRAINT user_group_pkey PRIMARY KEY ("user", "group")
);

-- auth.notify.function
CREATE OR REPLACE FUNCTION ${"schema"}.notify_table()
RETURNS trigger AS $$
DECLARE
    lock_id BIGINT;
BEGIN
    lock_id := hashtextextended(TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 0);
    IF pg_try_advisory_xact_lock(lock_id) THEN
        PERFORM pg_notify(
            ${'channel'},
            json_build_object(
                'schema', TG_TABLE_SCHEMA,
                'table', TG_TABLE_NAME,
                'action', TG_OP
            )::text
        );
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- auth.notify.user.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS user_table_changes_notify ON ${"schema"}.user;
    CREATE TRIGGER user_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}.user
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;

-- auth.notify.identity.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS identity_table_changes_notify ON ${"schema"}.identity;
    CREATE TRIGGER identity_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}.identity
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;

-- auth.notify.session.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS session_table_changes_notify ON ${"schema"}.session;
    CREATE TRIGGER session_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}.session
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;

-- auth.notify.apikey.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS apikey_table_changes_notify ON ${"schema"}.apikey;
    CREATE TRIGGER apikey_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}.apikey
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;

-- auth.notify.group.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS group_table_changes_notify ON ${"schema"}."group";
    CREATE TRIGGER group_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}."group"
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;

-- auth.notify.user_group.trigger
DO $$ BEGIN
    DROP TRIGGER IF EXISTS user_group_table_changes_notify ON ${"schema"}.user_group;
    CREATE TRIGGER user_group_table_changes_notify
    AFTER INSERT OR UPDATE OR DELETE ON ${"schema"}.user_group
    FOR EACH STATEMENT
    EXECUTE FUNCTION ${"schema"}.notify_table();
END $$;
