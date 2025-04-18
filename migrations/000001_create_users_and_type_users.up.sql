CREATE TABLE IF NOT EXISTS user_types
(
    user_type VARCHAR(25) PRIMARY KEY
);

INSERT INTO user_types
VALUES ('user'),     -- Customer placing orders
       ('admin'),    -- Admin having access to everything
       ('delivery'), -- Worker who delivers the orders to address
       ('workshop'); -- Worker who receive the order, pick, pack and pass the order to delivery

CREATE TABLE IF NOT EXISTS users
(
    id        UUID PRIMARY KEY,
    email     VARCHAR(255) NOT NULL UNIQUE,
    username  VARCHAR(255) NOT NULL UNIQUE,
    password  VARCHAR(255) NOT NULL UNIQUE,
    user_type VARCHAR(25) REFERENCES user_types (user_type)
)