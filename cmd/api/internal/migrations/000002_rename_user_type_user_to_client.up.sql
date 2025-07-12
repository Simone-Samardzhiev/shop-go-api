INSERT INTO user_types
VALUES ('client');

UPDATE users
SET user_type = 'client'
WHERE user_type = 'user';

DELETE
FROM user_types
WHERE user_type = 'user';