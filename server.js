require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const NODE_ENV = process.env.NODE_ENV || "development";
const JWT_SECRET = process.env.JWT_SECRET;
if (NODE_ENV === "production" && (!JWT_SECRET || JWT_SECRET.length < 16)) {
  console.error("Falta JWT_SECRET (o es muy corto) en producción.");
  process.exit(1);
}

function parseCorsOrigins() {
  // CORS_ORIGIN ejemplo:
  // - "http://localhost:5173,http://localhost:8888,https://tu-app.netlify.app"
  const raw = (process.env.CORS_ORIGIN || "").trim();
  const defaults = new Set([
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:8080",
    "https://nataback.netlify.app",
    "https://nataback.onrender.com",
  ]);
  if (!raw) return [...defaults];
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const d of defaults) parts.push(d);
  return [...new Set(parts)];
}

const corsOrigins = parseCorsOrigins();
app.use(
  cors({
    origin(origin, cb) {
      // Requests server-to-server o herramientas sin Origin (curl/postman)
      if (!origin) return cb(null, true);
      if (corsOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("CORS bloqueado para este origen: " + origin));
    },
    credentials: true,
  })
);

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

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const orderLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Demasiadas órdenes en un corto tiempo, intenta de nuevo más tarde.",
});

// Inicializa las tablas necesarias
async function initTables() {
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'mesero', 'bodega', 'caja')),
      active BOOLEAN NOT NULL DEFAULT TRUE
    );

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

    CREATE TABLE IF NOT EXISTS flavors (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      estado TEXT NOT NULL CHECK (estado IN ('bien', 'poco', 'nada')) DEFAULT 'bien'
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      mesero_id INTEGER REFERENCES users(id),
      client_plate TEXT,
      total INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending','cocinando','apunto_salida','entregado','cancelled')) DEFAULT 'pending',
      observation TEXT,
      paid BOOLEAN NOT NULL DEFAULT FALSE,
      payment_method TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS client_plate TEXT;

    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';

    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS observation TEXT;

    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS paid BOOLEAN NOT NULL DEFAULT FALSE;

    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS payment_method TEXT;

    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
      plate TEXT,
      location TEXT,
      size TEXT NOT NULL CHECK (size IN ('mini','pequeno', 'mediano', 'grande')),
      sabores TEXT[] NOT NULL,
      extras JSONB NOT NULL,
      observation TEXT,
      quantity INTEGER NOT NULL DEFAULT 1,
      total INTEGER NOT NULL
    );

    ALTER TABLE order_items
      ADD COLUMN IF NOT EXISTS observation TEXT;

    ALTER TABLE order_items
      ADD COLUMN IF NOT EXISTS quantity INTEGER NOT NULL DEFAULT 1;

    ALTER TABLE order_items
      DROP CONSTRAINT IF EXISTS order_items_size_check;

    ALTER TABLE order_items
      ADD CONSTRAINT order_items_size_check CHECK (size IN ('mini','pequeno','mediano','grande','galleta'));
  `;
  await pool.query(schema);
}

initTables().then(() => {
  console.log("Tablas inicializadas correctamente.");
}).catch(err => {
  console.error("Error al inicializar tablas:", err);
});
// Nota: el usuario administrador se crea con:
// `npm run init:admin` usando ADMIN_USERNAME / ADMIN_PASSWORD

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
    if (req.user.role === ROLES.ADMIN) {
      return next();
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Permisos insuficientes" });
    }
    next();
  };
}

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  console.log(`[AUTH] Login attempt for username=${username}`);
  if (!username || !password) {
    console.log('[AUTH] Missing credentials');
    return res.status(400).json({ error: "Faltan credenciales" });
  }
  try {
    const { rows } = await pool.query(
      "SELECT id, username, password_hash, role, active FROM users WHERE username = $1",
      [username]
    );
    if (rows.length > 0 && rows[0].active === false) {
      return res.status(403).json({ error: "Usuario desactivado" });
    }
    if (rows.length === 0) {
      console.log(`[AUTH] User not found: ${username}`);
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      console.log(`[AUTH] Invalid password for: ${username}`);
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }
    const token = generateToken(user);
    console.log(`[AUTH] Login successful for: ${username}`);
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error('[AUTH] Server error', e);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.get("/users", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  console.log(`[USERS] Admin ${req.user.username} requested user list`);
  try {
    const { rows } = await pool.query(
      "SELECT id, username, role, active FROM users ORDER BY id ASC"
    );
    res.json(rows);
  } catch (e) {
    console.error('[USERS] Error fetching users', e);
    res.status(500).json({ error: "Error al listar usuarios" });
  }
});

app.post("/users", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  const { username, password, role, active } = req.body;
  console.log(`[USERS] Admin ${req.user.username} creating user ${username} role=${role} active=${active}`);
  if (!username || !password || !role) {
    console.log('[USERS] Missing data for user creation');
    return res.status(400).json({ error: "Datos incompletos" });
  }
  if (![ROLES.MESERO, ROLES.BODEGA, ROLES.CAJA].includes(role)) {
    console.log(`[USERS] Invalid role provided: ${role}`);
    return res.status(400).json({ error: "Rol inválido" });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (username, password_hash, role, active) VALUES ($1,$2,$3,$4) RETURNING id, username, role, active",
      [username, hash, role, active === false ? false : true]
    );
    console.log(`[USERS] User created: ${rows[0].username}`);
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error('[USERS] Error creating user', e);
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

app.patch("/users/:id", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  const { id } = req.params;
  const { username, password, active, role } = req.body;
  try {
    const { rows: existing } = await pool.query("SELECT id, role FROM users WHERE id = $1", [id]);
    if (existing.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    if (existing[0].role === ROLES.ADMIN) {
      if (role && role !== ROLES.ADMIN) {
        return res.status(403).json({ error: "No se puede cambiar el rol de otro administrador" });
      }
      if (active === false) {
        return res.status(403).json({ error: "No se puede desactivar administrador" });
      }
    }

    const updates = [];
    const params = [];
    let idx = 1;

    if (username) {
      updates.push(`username = $${idx++}`);
      params.push(username);
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${idx++}`);
      params.push(hash);
    }
    if (active !== undefined) {
      updates.push(`active = $${idx++}`);
      params.push(active);
    }
    if (role) {
      if (![ROLES.ADMIN, ROLES.MESERO, ROLES.BODEGA, ROLES.CAJA].includes(role)) {
        return res.status(400).json({ error: "Rol inválido" });
      }
      updates.push(`role = $${idx++}`);
      params.push(role);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: "Ningún campo para actualizar" });
    }

    params.push(id);
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${idx} RETURNING id, username, role, active`;
    const { rows } = await pool.query(query, params);
    console.log(`[USERS] Admin ${req.user.username} updated user ${id}`);
    res.json(rows[0]);
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Nombre de usuario duplicado' });
    }
    console.error('[USERS] Error updating user', e);
    res.status(500).json({ error: "Error al actualizar usuario" });
  }
});

app.get("/stats", authMiddleware, requireRole(ROLES.ADMIN), async (req, res) => {
  try {
    const [daily, weekly, yearly] = await Promise.all([
      pool.query(
        `SELECT to_char(created_at, 'YYYY-MM-DD') AS period, COUNT(*) AS count, SUM(total) AS total
         FROM orders
         GROUP BY period
         ORDER BY period DESC
         LIMIT 30`
      ),
      pool.query(
        `SELECT to_char(date_trunc('week', created_at), 'IYYY-IW') AS period, COUNT(*) AS count, SUM(total) AS total
         FROM orders
         GROUP BY period
         ORDER BY period DESC
         LIMIT 12`
      ),
      pool.query(
        `SELECT date_part('year', created_at)::int AS period, COUNT(*) AS count, SUM(total) AS total
         FROM orders
         GROUP BY period
         ORDER BY period DESC`
      ),
    ]);

    const totalsRes = await pool.query(
      `SELECT
         COUNT(*) AS total_orders,
         COALESCE(SUM(total), 0) AS total_revenue,
         COALESCE(AVG(total), 0) AS avg_order_value,
         SUM(CASE WHEN created_at::date = CURRENT_DATE THEN 1 ELSE 0 END) AS today_orders,
         SUM(CASE WHEN created_at::date = CURRENT_DATE THEN total ELSE 0 END) AS today_revenue
       FROM orders`
    );

    const statusRes = await pool.query(
      `SELECT status, COUNT(*) AS count
       FROM orders
       GROUP BY status`
    );

    const topMeserosRes = await pool.query(
      `SELECT u.username, COUNT(o.id) AS orders_count, COALESCE(SUM(o.total),0) AS total_revenue
       FROM orders o
       JOIN users u ON u.id = o.mesero_id
       GROUP BY u.username
       ORDER BY orders_count DESC
       LIMIT 10`
    );

    const topSizesRes = await pool.query(
      `SELECT size, SUM(quantity) AS total_units, SUM(total) AS total_revenue
       FROM order_items
       GROUP BY size
       ORDER BY total_units DESC
       LIMIT 10`
    );

    const topSaboresRes = await pool.query(
      `SELECT sabor, SUM(quantity) AS total_units
       FROM (
         SELECT unnest(sabores) AS sabor, quantity
         FROM order_items
       ) AS sub
       GROUP BY sabor
       ORDER BY total_units DESC
       LIMIT 10`
    );

    res.json({
      daily: daily.rows,
      weekly: weekly.rows,
      yearly: yearly.rows,
      totals: totalsRes.rows[0],
      status_breakdown: statusRes.rows,
      top_meseros: topMeserosRes.rows,
      top_sizes: topSizesRes.rows,
      top_sabores: topSaboresRes.rows,
    });
  } catch (e) {
    console.error('[STATS] Error fetching stats', e);
    res.status(500).json({ error: 'Error al obtener estadísticas' });
  }
});

app.post(
  "/inventory",
  authMiddleware,
  requireRole(ROLES.BODEGA),
  async (req, res) => {
    const { nombre, estado } = req.body;
    console.log(`[INVENTORY] Bodega ${req.user.username} adding flavor ${nombre} (${estado})`);
    if (!nombre) {
      console.log('[INVENTORY] Missing flavor name');
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
      console.log(`[INVENTORY] Flavor created id=${rows[0].id} name=${rows[0].nombre}`);
      res.status(201).json(rows[0]);
    } catch (e) {
      console.error('[INVENTORY] Error creating flavor', e);
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

app.post("/orders", orderLimiter, authMiddleware, requireRole(ROLES.MESERO), async (req, res) => {
  const { items } = req.body;
  console.log(`[ORDERS] Mesero ${req.user.username} creating order with ${items?.length || 0} items`);
  if (!Array.isArray(items) || items.length === 0) {
    console.log('[ORDERS] No items provided for order');
    return res.status(400).json({ error: "Items requeridos" });
  }

  const PRICE_BY_SIZE = {
    mini: 2000,
    pequeno: 2500,
    mediano: 3000,
    grande: 4000,
    galleta: 500,
  };
  const EXTRA_GALLETA_PRICE = 500;
  const validLocations = new Set(["zona-a", "zona-b", "parqueadero", "patio"]);

  function normalizeString(s, maxLen) {
    if (typeof s !== "string") return "";
    const out = s.trim().replace(/\s+/g, " ");
    return out.slice(0, maxLen);
  }

  function normalizeSabores(arr) {
    if (!Array.isArray(arr)) return [];
    const clean = arr
      .map((s) => normalizeString(s, 40))
      .filter(Boolean);
    return [...new Set(clean)];
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const normalizedItems = [];
    let orderTotal = 0;
    let orderClientPlate = null;

    for (const it of items) {
      const size = normalizeString(it.size, 16);
      if (!Object.prototype.hasOwnProperty.call(PRICE_BY_SIZE, size)) {
        console.log(`[ORDERS] Tamaño inválido recibido: ${size}`);
        return res.status(400).json({ error: `Tamaño inválido: ${size}` });
      }

      const quantity = Number.isInteger(it.quantity) && it.quantity > 0 ? it.quantity : 1;
      const isCookie = size === "galleta";
      const sabores = normalizeSabores(it.sabores);
      if (!isCookie && sabores.length === 0) {
        return res.status(400).json({ error: "Cada helado debe tener al menos 1 sabor" });
      }
      if (isCookie && sabores.length === 0) {
        sabores.push("galleta");
      }

      const extras = typeof it.extras === "object" && it.extras ? it.extras : {};
      const extrasNormalized = {
        salsa: !!extras.salsa,
        tajin: !!extras.tajin,
        chispa: !!extras.chispa,
        galleta: Number.isInteger(extras.galleta) && extras.galleta > 0 ? extras.galleta : 0,
      };

      const location = normalizeString(it.location, 20);
      if (location && !validLocations.has(location)) {
        return res.status(400).json({ error: `Ubicación inválida: ${location}` });
      }

      const plate = normalizeString(it.plate, 12).toUpperCase();
      if (!plate) {
        return res.status(400).json({ error: "Placa o cliente es requerido en cada item" });
      }
      if (!orderClientPlate) orderClientPlate = plate;
      const observation = normalizeString(it.observation, 240);

      const base = PRICE_BY_SIZE[size];
      const extrasPrice = (extrasNormalized.galleta || 0) * EXTRA_GALLETA_PRICE;
      const itemTotal = (base + extrasPrice) * quantity;

      orderTotal += itemTotal;
      normalizedItems.push({
        plate: plate || null,
        location: location || null,
        size,
        sabores,
        extras: extrasNormalized,
        observation: observation || null,
        quantity,
        total: itemTotal,
      });
    }

    const orderPaid = !!req.body.paid;
    const paymentMethod = typeof req.body.payment_method === "string" ? normalizeString(req.body.payment_method, 50) : null;

    const orderRes = await client.query(
      "INSERT INTO orders (mesero_id, client_plate, total, status, observation, paid, payment_method) VALUES ($1,$2,$3,'pending', $4,$5,$6) RETURNING id",
      [req.user.id, orderClientPlate, orderTotal, req.body.observation ? normalizeString(req.body.observation, 240) : null, orderPaid, paymentMethod]
    );
    const orderId = orderRes.rows[0].id;
    for (const it of normalizedItems) {
      await client.query(
        `INSERT INTO order_items 
        (order_id, plate, location, size, sabores, extras, observation, quantity, total) 
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          orderId,
          it.plate || null,
          it.location || null,
          it.size,
          it.sabores,
          it.extras,
          it.observation,
          it.quantity,
          it.total,
        ]
      );
    }
    await client.query("COMMIT");
    console.log(`[ORDERS] Order created id=${orderId} total=${orderTotal}`);
    res.status(201).json({ id: orderId });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error('[ORDERS] Error creating order', e);
    res.status(500).json({ error: "Error al crear pedido" });
  } finally {
    client.release();
  }
});

app.get("/orders", authMiddleware, requireRole(ROLES.CAJA), async (req, res) => {
  try {
    const dateFilter = req.query.date || null;
    let ordersRes;
    if (dateFilter) {
      ordersRes = await pool.query(
        "SELECT id, client_plate, total, status, observation, paid, payment_method, created_at FROM orders WHERE created_at::date = $1 ORDER BY created_at DESC",
        [dateFilter]
      );
    } else {
      ordersRes = await pool.query(
        "SELECT id, client_plate, total, status, observation, paid, payment_method, created_at FROM orders WHERE created_at::date = CURRENT_DATE ORDER BY created_at DESC"
      );
    }
    const orders = ordersRes.rows;
    const itemsRes = await pool.query(
      "SELECT id, order_id, plate, location, size, sabores, extras, observation, quantity, total FROM order_items ORDER BY id ASC"
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
        observation: it.observation || "",
        quantity: it.quantity || 1,
        total: it.total,
      });
    }
    const formatted = orders.map((o) => ({
      id: o.id,
      client_plate: o.client_plate || null,
      total: o.total,
      status: o.status,
      observation: o.observation || "",
      paid: o.paid,
      payment_method: o.payment_method || null,
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

app.get("/orders/recent", authMiddleware, requireRole(ROLES.CAJA, ROLES.MESERO), async (req, res) => {
  try {
    const ordersRes = await pool.query(
      "SELECT id, client_plate, total, status, observation, paid, payment_method, created_at FROM orders ORDER BY created_at DESC LIMIT 20"
    );
    const orders = ordersRes.rows;
    const itemsRes = await pool.query(
      "SELECT id, order_id, plate, location, size, sabores, extras, observation, quantity, total FROM order_items WHERE order_id = ANY($1) ORDER BY id ASC",
      [orders.map((o) => o.id)]
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
        observation: it.observation || "",
        quantity: it.quantity || 1,
        total: it.total,
      });
    }
    const formatted = orders.map((o) => ({
      id: o.id,
      client_plate: o.client_plate || null,
      total: o.total,
      status: o.status,
      observation: o.observation || "",
      paid: o.paid,
      payment_method: o.payment_method || null,
      created_at: o.created_at,
      created_at_readable: new Date(o.created_at).toLocaleString("es-CO"),
      items: itemsByOrder[o.id] || [],
    }));
    res.json(formatted);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al listar pedidos recientes" });
  }
});

app.get("/orders/mine", authMiddleware, requireRole(ROLES.MESERO), async (req, res) => {
  try {
    const ordersRes = await pool.query(
      "SELECT id, client_plate, total, status, observation, paid, payment_method, created_at FROM orders WHERE mesero_id = $1 AND created_at::date = CURRENT_DATE ORDER BY created_at DESC",
      [req.user.id]
    );
    const orders = ordersRes.rows;
    const itemsRes = await pool.query(
      "SELECT id, order_id, plate, location, size, sabores, extras, observation, quantity, total FROM order_items ORDER BY id ASC"
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
        observation: it.observation || "",
        quantity: it.quantity || 1,
        total: it.total,
      });
    }
    const formatted = orders.map((o) => ({
      id: o.id,
      client_plate: o.client_plate || null,
      total: o.total,
      status: o.status,
      observation: o.observation || "",
      paid: o.paid,
      payment_method: o.payment_method || null,
      created_at: o.created_at,
      created_at_readable: new Date(o.created_at).toLocaleString("es-CO"),
      items: itemsByOrder[o.id] || [],
    }));
    res.json(formatted);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al listar mis pedidos" });
  }
});

app.patch("/orders/:id/status", authMiddleware, requireRole(ROLES.CAJA), async (req, res) => {
  const { id } = req.params;
  const { status, observation } = req.body;
  const validStatuses = ["pending", "cocinando", "apunto_salida", "entregado", "cancelled"];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: "Estado inválido" });
  }

  try {
    const current = await pool.query("SELECT status FROM orders WHERE id = $1", [id]);
    if (current.rows.length === 0) return res.status(404).json({ error: "Pedido no encontrado" });
    const curStatus = current.rows[0].status;
    if (curStatus === "cancelled") return res.status(400).json({ error: "No se puede editar pedido cancelado" });
    if (curStatus === "entregado") return res.status(400).json({ error: "No se puede cambiar un pedido entregado" });

    const allowedTransitions = {
      pending: ["cocinando", "apunto_salida", "entregado", "cancelled"],
      cocinando: ["apunto_salida", "entregado", "cancelled"],
      apunto_salida: ["entregado", "cancelled"],
    };

    if (!allowedTransitions[curStatus]?.includes(status)) {
      return res.status(400).json({ error: `Transición no permitida: ${curStatus} -> ${status}` });
    }

    const order = await pool.query("UPDATE orders SET status = $1, observation = COALESCE($2, observation) WHERE id = $3 RETURNING id, status, observation", [status, observation || null, id]);
    res.json(order.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al actualizar estado" });
  }
});

app.patch("/orders/:id/cancel", authMiddleware, requireRole(ROLES.MESERO), async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query("SELECT mesero_id, status FROM orders WHERE id = $1", [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: "Pedido no encontrado" });
    if (check.rows[0].mesero_id !== req.user.id) return res.status(403).json({ error: "No puede cancelar pedido de otro mesero" });
    if (check.rows[0].status === "cancelled") return res.status(400).json({ error: "Pedido ya cancelado" });

    await pool.query("UPDATE orders SET status = 'cancelled' WHERE id = $1", [id]);
    console.log(`[ORDERS] Pedido ${id} cancelado por mesero ${req.user.username}`);
    res.json({ success: true, message: "Pedido cancelado" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al cancelar pedido" });
  }
});

app.get("/", (req, res) => {
  res.send("API Crema de Nata funcionando");
});

app.listen(PORT, () => {
  console.log(`Servidor Crema de Nata en puerto ${PORT}`);
});

