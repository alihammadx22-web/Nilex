CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    refresh_token_hash CHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_auth_sessions_user
        FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE,
    CONSTRAINT ck_auth_sessions_refresh_hash_length
        CHECK (char_length(refresh_token_hash) = 64)
);

CREATE UNIQUE INDEX ux_auth_sessions_refresh_token_hash
    ON auth_sessions (refresh_token_hash);

CREATE UNIQUE INDEX ux_auth_sessions_one_active_per_user
    ON auth_sessions (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX ix_auth_sessions_user_id
    ON auth_sessions (user_id);
