-- Apaga tabelas se já existirem
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS friend_requests;
DROP TABLE IF EXISTS friends;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS conversations;
DROP TABLE IF EXISTS conversation_messages;

-- Criação da tabela de utilizadores
CREATE TABLE users (
    username    VARCHAR(32) PRIMARY KEY,
    password    VARCHAR(512) NOT NULL,
    salt        VARCHAR(512) NOT NULL,
    totp_secret VARCHAR(512),   -- Chave secreta para MFA TOTP (NULL se MFA não estiver ativo)
    mfa_enabled BOOLEAN DEFAULT FALSE -- Indica se o utilizador ativou MFA
);

-- Criação da tabela de pedidos de amizade
CREATE TABLE friend_requests (
    id SERIAL PRIMARY KEY,
    sender VARCHAR(32) NOT NULL,
    receiver VARCHAR(32) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (receiver) REFERENCES users(username) ON DELETE CASCADE
);

-- Criação da tabela de amigos
CREATE TABLE friends (
    id SERIAL PRIMARY KEY,
    user1 VARCHAR(32) NOT NULL,
    user2 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (user2) REFERENCES users(username) ON DELETE CASCADE
);

-- Criação da tabela de conversas
CREATE TABLE conversations (
    conversation_id SERIAL PRIMARY KEY,
    user1 VARCHAR(32) NOT NULL,
    user2 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user1, user2),
    FOREIGN KEY (user1) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (user2) REFERENCES users(username) ON DELETE CASCADE
);

-- Criação da tabela de mensagens associadas a uma conversa
CREATE TABLE conversation_messages (
    message_id SERIAL PRIMARY KEY,
    conversation_id INT NOT NULL,
    sender VARCHAR(32) NOT NULL,
    message TEXT NOT NULL,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE
);






