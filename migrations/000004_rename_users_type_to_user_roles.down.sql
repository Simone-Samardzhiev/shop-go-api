ALTER TABLE IF EXISTS user_roles
    RENAME TO user_types;


ALTER TABLE users
    RENAME COLUMN user_role TO user_type;