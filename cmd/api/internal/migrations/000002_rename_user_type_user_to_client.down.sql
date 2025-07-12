INSERT INTO user_types
VALUES ('user');

UPDATE users
SET user_type = 'user'
WHERE user_type = 'client';

DELETE
FROM user_types
WHERE user_type = 'client';