ALTER TABLE IF EXISTS user_types
    RENAME TO user_roles;

ALTER TABLE users
    RENAME COLUMN user_type TO user_role;