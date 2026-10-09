ALTER TABLE app_users
    ADD COLUMN google_sub VARCHAR(255);

ALTER TABLE app_users
    ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE app_users
    DROP CONSTRAINT ck_app_users_password_hash_not_blank;

ALTER TABLE app_users
    ADD CONSTRAINT ck_app_users_password_hash_not_blank
        CHECK (password_hash IS NULL OR btrim(password_hash) <> ''),
    ADD CONSTRAINT ck_app_users_google_sub_not_blank
        CHECK (google_sub IS NULL OR btrim(google_sub) <> ''),
    ADD CONSTRAINT ck_app_users_authentication_method
        CHECK (password_hash IS NOT NULL OR google_sub IS NOT NULL);

CREATE UNIQUE INDEX ux_app_users_google_sub
    ON app_users (google_sub)
    WHERE google_sub IS NOT NULL;
