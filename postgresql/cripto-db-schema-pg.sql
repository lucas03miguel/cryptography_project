DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;

CREATE TABLE users (
    username    VARCHAR( 32)    primary key,
    password    VARCHAR(512)    NOT NULL,
    salt        VARCHAR(512)    NOT NULL,
    totp_secret VARCHAR(512),   -- Chave secreta para MFA TOTP (NULL se MFA não estiver ativo)
    mfa_enabled BOOLEAN         DEFAULT FALSE -- Indica se o utilizador ativou MFA
);

CREATE TABLE friend_requests (
    id SERIAL PRIMARY KEY,
    sender VARCHAR(32) NOT NULL,
    receiver VARCHAR(32) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE friends (
    id SERIAL PRIMARY KEY,
    user1 VARCHAR(32) NOT NULL,
    user2 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE messages (
    message_id  SERIAL PRIMARY KEY,
    author      VARCHAR( 16)   ,
    message     VARCHAR(256)    NOT NULL
);


-- Default data for messages
insert into messages (author, message)
values ('Vulnerable', 'Hi! I wrote this message using Vulnerable Form.');

insert into messages (author, message)
values ('Correct', 'OMG! This form is so correct!!!');

insert into messages (author, message)
values ('Vulnerable', 'Oh really?');




