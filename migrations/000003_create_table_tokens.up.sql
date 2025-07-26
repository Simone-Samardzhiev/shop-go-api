CREATE TABLE IF NOT EXISTS tokens
(
    id      UUID PRIMARY KEY NOT NULL,
    user_id UUID REFERENCES users (id),
    exp     TIMESTAMP        NOT NULL
)