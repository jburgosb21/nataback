require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-crema-de-nata";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const ROLES = {
  ADMIN: "admin",
  MESERO: "mesero",
  BODEGA: "bodega",
  CAJA: "caja",
};

// Inicializa las tablas necesarias
async function initTables() {
  const schema = `
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
      size TEXT NOT NULL CHECK (size IN ('pequeno', 'mediano', 'grande')),
      sabores TEXT[] NOT NULL,
      extras JSONB NOT NULL,
      total INTEGER NOT NULL
    );
  `;
  await pool.query(schema);
}

initTables().then(() => {
  console.log("Tablas inicializadas correctamente.");
}).catch(err => {
  console.error("Error al inicializar tablas:", err);
});
// Crear usuario administrador 'nata' si no existe
async function createAdminUser() {
  const username = 'nata';
  const password = '123456';
  const role = ROLES.ADMIN;
  const hash = await bcrypt.hash(password, 10);
  const res = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (res.rows.length === 0) {
    await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)',
      [username, hash, role]
    );
    console.log('Usuario administrador "nata" creado.');
  } else {
    console.log('Usuario administrador "nata" ya existe.');
  }
}

createAdminUser().catch(err => {
  console.error('Error creando usuario administrador:', err);
});

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Sin token" });
  const [, token] = header.split(" ");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "No autorizado" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Permisos insuficientes" });
    }
    next();
  };
}

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Faltan credenciales" });
  }
  try {
    const { rows } = await pool.query(
      "SELECT id, username, password_hash, role FROM users WHERE username = $1",
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }
    const token = generateToken(user);
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.get("/users", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, role FROM users ORDER BY id ASC"
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al listar usuarios" });
  }
});

app.post("/users", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: "Datos incompletos" });
  }
  if (![ROLES.MESERO, ROLES.BODEGA, ROLES.CAJA].includes(role)) {
    return res.status(400).json({ error: "Rol inválido" });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id, username, role",
      [username, hash, role]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al crear usuario" });
  }
});

app.get(
  "/inventory",
  authMiddleware,
  requireRole(ROLES.BODEGA, ROLES.MESERO),
  async (req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, nombre, estado FROM flavors ORDER BY id ASC"
      );
      res.json(rows);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error al listar inventario" });
    }
  }
);

app.post(
  "/inventory",
  authMiddleware,
  requireRole(ROLES.BODEGA),
  async (req, res) => {
    const { nombre, estado } = req.body;
    if (!nombre) {
      return res.status(400).json({ error: "Nombre requerido" });
    }
    const finalEstado = ["bien", "poco", "nada"].includes(estado)
      ? estado
      : "bien";
    try {
      const { rows } = await pool.query(
        "INSERT INTO flavors (nombre, estado) VALUES ($1,$2) RETURNING id, nombre, estado",
        [nombre, finalEstado]
      );
      res.status(201).json(rows[0]);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error al crear sabor" });
    }
  }
);

app.patch(
  "/inventory/:id",
  authMiddleware,
  requireRole(ROLES.BODEGA),
  async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;
    if (!["bien", "poco", "nada"].includes(estado)) {
      return res.status(400).json({ error: "Estado inválido" });
    }
    try {
      const { rows } = await pool.query(
        "UPDATE flavors SET estado=$1 WHERE id=$2 RETURNING id, nombre, estado",
        [estado, id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: "Sabor no encontrado" });
      }
      res.json(rows[0]);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error al actualizar sabor" });
    }
  }
);

app.get("/menu", authMiddleware, requireRole(ROLES.MESERO), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, nombre, estado FROM flavors ORDER BY id ASC"
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al obtener menú" });
  }
});

app.post("/orders", authMiddleware, requireRole(ROLES.MESERO), async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Items requeridos" });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const orderTotal = items.reduce((sum, it) => sum + (it.total || 0), 0);
    const orderRes = await client.query(
      "INSERT INTO orders (mesero_id, total) VALUES ($1,$2) RETURNING id",
      [req.user.id, orderTotal]
    );
    const orderId = orderRes.rows[0].id;
    for (const it of items) {
      await client.query(
        `INSERT INTO order_items 
        (order_id, plate, location, size, sabores, extras, total) 
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          orderId,
          it.plate || null,
          it.location || null,
          it.size,
          it.sabores,
          it.extras,
          it.total,
        ]
      );
    }
    await client.query("COMMIT");
    res.status(201).json({ id: orderId });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "Error al crear pedido" });
  } finally {
    client.release();
  }
});

app.get("/orders", authMiddleware, requireRole(ROLES.CAJA), async (req, res) => {
  try {
    const ordersRes = await pool.query(
      "SELECT id, total, created_at FROM orders ORDER BY created_at DESC LIMIT 50"
    );
    const orders = ordersRes.rows;
    const itemsRes = await pool.query(
      "SELECT id, order_id, plate, location, size, sabores, extras, total FROM order_items ORDER BY id ASC"
    );
    const itemsByOrder = {};
    for (const it of itemsRes.rows) {
      if (!itemsByOrder[it.order_id]) itemsByOrder[it.order_id] = [];
      itemsByOrder[it.order_id].push({
        id: it.id,
        plate: it.plate,
        location: it.location,
        size: it.size,
        sabores: it.sabores,
        extras: it.extras,
        total: it.total,
      });
    }
    const formatted = orders.map((o) => ({
      id: o.id,
      total: o.total,
      created_at: o.created_at,
      created_at_readable: new Date(o.created_at).toLocaleString("es-CO"),
      items: itemsByOrder[o.id] || [],
    }));
    res.json(formatted);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al listar pedidos" });
  }
});

app.get("/", (req, res) => {
  res.send("API Crema de Nata funcionando");
});

app.listen(PORT, () => {
  console.log(`Servidor Crema de Nata en puerto ${PORT}`);
});

