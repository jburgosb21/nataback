require("dotenv").config();
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error("Falta DATABASE_URL en el entorno");
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  const username = process.env.ADMIN_USERNAME || "admin";
  const password = process.env.ADMIN_PASSWORD || "admin123";

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'mesero', 'bodega', 'caja'))
      )
    `);

    const { rows } = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (rows.length > 0) {
      console.log("El usuario administrador ya existe:", username);
    } else {
      await pool.query(
        "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)",
        [username, hash, "admin"]
      );
      console.log("Usuario administrador creado:");
      console.log("  usuario:", username);
      console.log("  contraseña:", password);
    }
  } catch (e) {
    console.error("Error creando usuario admin:", e);
  } finally {
    await pool.end();
  }
}

main();

