-- Base de datos de GymApp
-- Ejecutar con:  mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS gymapp
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE gymapp;

CREATE TABLE IF NOT EXISTS usuarios (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(100) NOT NULL,
  correo        VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  creado_en     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rutinas (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  nombre         VARCHAR(100) NOT NULL,
  grupo_muscular VARCHAR(30)  NOT NULL,
  series         INT          NOT NULL,
  repeticiones   INT          NOT NULL,
  nivel          VARCHAR(20)  NOT NULL,
  activa         BOOLEAN      NOT NULL DEFAULT TRUE,
  usuario_id     INT          NOT NULL,
  creado_en      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT chk_series CHECK (series BETWEEN 1 AND 10),
  CONSTRAINT chk_repeticiones CHECK (repeticiones BETWEEN 1 AND 50),
  CONSTRAINT fk_rutinas_usuario FOREIGN KEY (usuario_id)
    REFERENCES usuarios (id) ON DELETE CASCADE
);