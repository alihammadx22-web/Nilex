CREATE TABLE app_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(120) NOT NULL,
    email VARCHAR(320) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'USER',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_app_users_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT ck_app_users_email_not_blank CHECK (btrim(email) <> ''),
    CONSTRAINT ck_app_users_password_hash_not_blank CHECK (btrim(password_hash) <> ''),
    CONSTRAINT ck_app_users_role CHECK (role IN ('USER', 'ADMIN'))
);

CREATE UNIQUE INDEX ux_app_users_email_ci ON app_users (lower(email));
