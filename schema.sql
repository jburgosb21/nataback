-- Esquema sugerido para Neon (Postgres) para Crema de Nata

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'mesero', 'bodega', 'caja'))
);

CREATE TABLE IF NOT EXISTS flavors (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  estado TEXT NOT NULL CHECK (estado IN ('bien', 'poco', 'nada')) DEFAULT 'bien'
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  mesero_id INTEGER REFERENCES users(id),
  total INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS order_items (
  id SERIAL PRIMARY KEY,
  order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
  plate TEXT,
  location TEXT,
  size TEXT NOT NULL CHECK (size IN ('mini', 'pequeno', 'mediano', 'grande', 'galleta')),
  sabores TEXT[] NOT NULL,
  extras JSONB NOT NULL,
  total INTEGER NOT NULL
);

-- Crear usuario administrador inicial (ajusta la contraseña hasheada desde Node)
-- INSERT se hace desde un script de inicialización en Node para evitar poner hashes aquí.

