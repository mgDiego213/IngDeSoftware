// ------------------------
// server.js (OrumGS) — Twelve Data only
// ------------------------
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

/* ============================
   MongoDB
   ============================ */
const MONGO_URI =
  process.env.MONGO_URI || process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/orumgs";
mongoose.set("strictQuery", true);
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch((e) => console.error("Error conectando a MongoDB:", e.message));

/* ============================
   Modelo de Usuario
   ============================ */
const userSchema = new mongoose.Schema(
  {
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    rol: { type: String, default: "Usuario" },
    resetPasswordTokenHash: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

/* ============================
   Auth Helpers
   ============================ */
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
function signToken(user) {
  return jwt.sign({ id: user._id.toString(), rol: user.rol, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}
function verifyToken(req, res, next) {
  try {
    const auth = req.headers["authorization"] || req.headers["Authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
    if (!token) return res.status(401).json({ message: "No autorizado" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Token inválido o expirado" });
  }
}

/* ============================
   Estáticos
   ============================ */
const ROOT_DIR = __dirname;
app.use(express.static(ROOT_DIR));
app.get("/", (_req, res) => res.sendFile(path.join(ROOT_DIR, "index.html")));
["/Inicio.html", "/Mercados.html", "/Administracion.html", "/reset.html"].forEach((route) => {
  app.get(route, (_req, res) => res.sendFile(path.join(ROOT_DIR, route.replace("/", ""))));
});

/* ============================
   Auth Endpoints
   ============================ */
app.post("/register", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ message: "Faltan campos" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "El correo ya está registrado" });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ nombre, email, password: hash, rol: "Usuario" });
    res.json({ message: "Usuario registrado", id: user._id.toString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al registrar" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Credenciales incorrectas" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Credenciales incorrectas" });
    const token = signToken(user);
    res.json({ token, rol: user.rol, userId: user._id.toString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error en login" });
  }
});

app.post("/validate-token", (req, res) => {
  try {
    const auth = req.headers["authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
    if (!token) return res.status(401).json({ message: "No autorizado" });
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ ok: true, user: decoded });
  } catch {
    res.status(401).json({ message: "Token inválido o expirado" });
  }
});

/* ============================
   Reset Password (Brevo)
   ============================ */
const MAIL_FROM = process.env.MAIL_FROM || "no-reply@example.com";
const CLIENT_URL = process.env.CLIENT_URL || "";
const SMTP_HOST = process.env.SMTP_HOST || "smtp-relay.brevo.com";
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "587", 10);
const SMTP_USER = process.env.SMTP_USER || "apikey";
const SMTP_PASS = process.env.SMTP_PASS || process.env.BREVO_SMTP_KEY || "";

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

app.post("/auth/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email requerido" });
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: "Si el correo existe, te enviaremos un enlace" });

    const tokenPlain = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(tokenPlain).digest("hex");

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 1000 * 60 * 60);
    await user.save();

    const resetLink = `${
      CLIENT_URL ? CLIENT_URL.replace(/\/+$/, "") : ""
    }/reset.html?token=${tokenPlain}&email=${encodeURIComponent(email)}`;
    await transporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "Restablecer contraseña",
      html: `<p>Solicitaste restablecer tu contraseña.</p><p>Enlace válido 1 hora:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
    });

    res.json({ message: "Si el correo existe, te enviaremos un enlace" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al solicitar restablecimiento" });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, email, password } = req.body;
    if (!token || !email || !password)
      return res.status(400).json({ message: "Datos incompletos" });
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      email,
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) return res.status(400).json({ message: "Token inválido o expirado" });
    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordTokenHash = null;
    user.resetPasswordExpires = null;
    await user.save();
    res.json({ message: "Contraseña actualizada. Ya puedes iniciar sesión." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al restablecer la contraseña" });
  }
});

/* ============================
   Top 30 (Solo Crypto + Forex)
   ============================ */
const TOP30 = [
  // CRYPTO (pares vs USDT)
  { key:"BTCUSDT", type:"crypto", label:"BTCUSDT (Bitcoin)",        tv_symbol:"BINANCE:BTCUSDT" },
  { key:"ETHUSDT", type:"crypto", label:"ETHUSDT (Ethereum)",       tv_symbol:"BINANCE:ETHUSDT" },
  { key:"BNBUSDT", type:"crypto", label:"BNBUSDT (BNB)",            tv_symbol:"BINANCE:BNBUSDT" },
  { key:"SOLUSDT", type:"crypto", label:"SOLUSDT (Solana)",         tv_symbol:"BINANCE:SOLUSDT" },
  { key:"XRPUSDT", type:"crypto", label:"XRPUSDT (XRP)",            tv_symbol:"BINANCE:XRPUSDT" },
  { key:"ADAUSDT", type:"crypto", label:"ADAUSDT (Cardano)",        tv_symbol:"BINANCE:ADAUSDT" },
  { key:"DOGEUSDT",type:"crypto", label:"DOGEUSDT (Dogecoin)",      tv_symbol:"BINANCE:DOGEUSDT"},
  { key:"AVAXUSDT",type:"crypto", label:"AVAXUSDT (Avalanche)",     tv_symbol:"BINANCE:AVAXUSDT"},
  { key:"TRXUSDT", type:"crypto", label:"TRXUSDT (TRON)",           tv_symbol:"BINANCE:TRXUSDT" },
  { key:"TONUSDT", type:"crypto", label:"TONUSDT (TON)",            tv_symbol:"BINANCE:TONUSDT" },
  { key:"LINKUSDT",type:"crypto", label:"LINKUSDT (Chainlink)",     tv_symbol:"BINANCE:LINKUSDT"},
  { key:"MATICUSDT",type:"crypto",label:"MATICUSDT (Polygon)",      tv_symbol:"BINANCE:MATICUSDT"},
  { key:"DOTUSDT", type:"crypto", label:"DOTUSDT (Polkadot)",       tv_symbol:"BINANCE:DOTUSDT" },
  { key:"LTCUSDT", type:"crypto", label:"LTCUSDT (Litecoin)",       tv_symbol:"BINANCE:LTCUSDT" },
  { key:"BCHUSDT", type:"crypto", label:"BCHUSDT (Bitcoin Cash)",   tv_symbol:"BINANCE:BCHUSDT" },
  { key:"ATOMUSDT",type:"crypto", label:"ATOMUSDT (Cosmos)",        tv_symbol:"BINANCE:ATOMUSDT"},
  { key:"ARBUSDT", type:"crypto", label:"ARBUSDT (Arbitrum)",       tv_symbol:"BINANCE:ARBUSDT" },
  { key:"OPUSDT",  type:"crypto", label:"OPUSDT (Optimism)",        tv_symbol:"BINANCE:OPUSDT"  },

  // FOREX
  { key:"EURUSD", type:"forex", label:"EURUSD", tv_symbol:"FX:EURUSD", fx:{base:"EUR",quote:"USD"} },
  { key:"USDJPY", type:"forex", label:"USDJPY", tv_symbol:"FX:USDJPY", fx:{base:"USD",quote:"JPY"} },
  { key:"GBPUSD", type:"forex", label:"GBPUSD", tv_symbol:"FX:GBPUSD", fx:{base:"GBP",quote:"USD"} },
  { key:"USDCHF", type:"forex", label:"USDCHF", tv_symbol:"FX:USDCHF", fx:{base:"USD",quote:"CHF"} },
  { key:"AUDUSD", type:"forex", label:"AUDUSD", tv_symbol:"FX:AUDUSD", fx:{base:"AUD",quote:"USD"} },
  { key:"USDCAD", type:"forex", label:"USDCAD", tv_symbol:"FX:USDCAD", fx:{base:"USD",quote:"CAD"} },
  { key:"EURJPY", type:"forex", label:"EURJPY", tv_symbol:"FX:EURJPY", fx:{base:"EUR",quote:"JPY"} },
  { key:"GBPJPY", type:"forex", label:"GBPJPY", tv_symbol:"FX:GBPJPY", fx:{base:"GBP",quote:"JPY"} },
];

app.get("/top30-list", (_req, res) => res.json(TOP30));

/* ============================
   Cache y Config
   ============================ */
const marketCache = new Map(); // "keys=BTCUSDT,EURUSD" -> { t, data }
const CACHE_TTL_MS = parseInt(process.env.MARKET_CACHE_TTL_MS || "60000", 10); // 60s

/* ============================
   TWELVE DATA — Config + Helpers + Logging
   ============================ */
const TWELVE_API_KEY = (process.env.TWELVE_API_KEY || "").trim();
if (!TWELVE_API_KEY) {
  console.warn("[TwelveData] TWELVE_API_KEY no está definido. Los precios responderán null.");
} else {
  console.log("[TwelveData] API key cargada:", TWELVE_API_KEY.slice(0, 3) + "..." + TWELVE_API_KEY.slice(-3));
}
console.log("[Market] CACHE_TTL_MS:", CACHE_TTL_MS, "ms");

// Mapa de tus keys -> símbolo Twelve Data
const TD_SYMBOL_MAP = {
  // CRYPTO
  "BTCUSDT": "BTC/USDT",
  "ETHUSDT": "ETH/USDT",
  "BNBUSDT": "BNB/USDT",
  "SOLUSDT": "SOL/USDT",
  "XRPUSDT": "XRP/USDT",
  "ADAUSDT": "ADA/USDT",
  "DOGEUSDT":"DOGE/USDT",
  "AVAXUSDT":"AVAX/USDT",
  "TRXUSDT": "TRX/USDT",
  "TONUSDT": "TON/USDT",
  "LINKUSDT":"LINK/USDT",
  "MATICUSDT":"MATIC/USDT",
  "DOTUSDT": "DOT/USDT",
  "LTCUSDT": "LTC/USDT",
  "BCHUSDT": "BCH/USDT",
  "ATOMUSDT":"ATOM/USDT",
  "ARBUSDT": "ARB/USDT",
  "OPUSDT":  "OP/USDT",
  // FOREX
  "EURUSD": "EUR/USD",
  "USDJPY": "USD/JPY",
  "GBPUSD": "GBP/USD",
  "USDCHF": "USD/CHF",
  "AUDUSD": "AUD/USD",
  "USDCAD": "USD/CAD",
  "EURJPY": "EUR/JPY",
  "GBPJPY": "GBP/JPY",
};

// Cliente axios con logging explícito
const tdClient = axios.create({
  baseURL: "https://api.twelvedata.com",
  timeout: 15000,
  // dejamos validateStatus por defecto; manejamos errores en catch
});

// Log centralizado de errores/bloqueos
function logTwelveError(ctx, err) {
  const code = err?.response?.status || err?.code || "UNKNOWN";
  const data = err?.response?.data;
  const headers = err?.response?.headers || {};
  const limit = headers["x-ratelimit-limit"] || headers["rate-limit-limit"];
  const remaining = headers["x-ratelimit-remaining"] || headers["rate-limit-remaining"];
  const reset = headers["x-ratelimit-reset"] || headers["rate-limit-reset"];
  const msg = (data && (data.message || data.note || JSON.stringify(data))) || err?.message || String(err);

  const isBlocked = [401, 402, 403, 429].includes(Number(code));
  const tag = isBlocked ? "BLOCKED" : "ERROR";

  console.error(`[TwelveData][${tag}] ctx=${ctx} status=${code} msg=${msg} ` +
    (limit || remaining || reset ? `rate{limit=${limit} remaining=${remaining} reset=${reset}}` : ""));
}

// Batch de precios: /price?symbol=A,B,C
async function tdBatchPrices(symbols) {
  if (!symbols.length || !TWELVE_API_KEY) return {};
  try {
    const url = `/price?symbol=${encodeURIComponent(symbols.join(","))}&apikey=${TWELVE_API_KEY}`;
    const res = await tdClient.get(url);
    const data = res.data;

    // Si Twelve Data devolvió error estructurado
    if (data && data.code && data.message) {
      logTwelveError("price-batch(payload)", { response: { status: data.code, data } });
      return {};
    }

    // Normaliza respuesta a objeto {symbol: price}
    const out = {};
    if (Array.isArray(data)) {
      for (const row of data) {
        const p = Number(row?.price);
        if (row?.symbol && Number.isFinite(p)) out[row.symbol] = p;
      }
    } else if (data && typeof data === "object") {
      for (const [sym, node] of Object.entries(data)) {
        const p = Number(node?.price);
        if (Number.isFinite(p)) out[sym] = p;
      }
    }
    return out;
  } catch (err) {
    logTwelveError("price-batch(request)", err);
    return {};
  }
}

/* ============================
   Precios unificados (Twelve Data)
   ============================ */
/**
 * GET /market-prices?keys=BTCUSDT,EURUSD
 * Respuesta: { items: [{ key, type, label, price_usd }] }
 * Fuente: Twelve Data (batch) · Cache TTL: 60s
 */
app.get("/market-prices", async (req, res) => {
  try {
    const keys = String(req.query.keys || "")
      .split(",").map(s => s.trim()).filter(Boolean);
    if (!keys.length) return res.json({ items: [] });

    // micro-cache por conjunto de keys
    const cacheKey = "keys=" + keys.join(",");
    const hit = marketCache.get(cacheKey);
    const now = Date.now();
    if (hit && now - hit.t < CACHE_TTL_MS) return res.json(hit.data);

    // Normaliza contra TOP30 y arma lista de símbolos TD
    const reqItems = keys.map(k => TOP30.find(x => x.key === k)).filter(Boolean);
    const tdSymbols = [];
    const keyToTd = {};
    for (const it of reqItems) {
      const tdSym = TD_SYMBOL_MAP[it.key];
      keyToTd[it.key] = tdSym || null;
      if (tdSym) tdSymbols.push(tdSym);
    }

    // Llamada batch a Twelve Data
    const tdMap = await tdBatchPrices([...new Set(tdSymbols)]);

    // Respuesta en el mismo orden pedido
    const items = reqItems.map(it => {
      const tdSym = keyToTd[it.key];
      const price = tdSym ? tdMap[tdSym] : null;
      return {
        key: it.key,
        type: it.type,
        label: it.label,
        price_usd: Number.isFinite(price) ? price : null
      };
    });

    const payload = { items };
    marketCache.set(cacheKey, { t: now, data: payload });
    res.json(payload);
  } catch (e) {
    console.error("market-prices (TD) error:", e?.message || e);
    res.status(502).json({ items: [] });
  }
});

/**
 * GET /crypto-prices
 * - Shape: { bitcoin:{usd}, ethereum:{usd}, dogecoin:{usd} }
 * - Fuente: Twelve Data (BTC/USDT, ETH/USDT, DOGE/USDT)
 */
// === /crypto-prices (Twelve Data) con micro-cache de 60s ===
app.get("/crypto-prices", async (_req, res) => {
  try {
    const cacheKey = "crypto-dashboard";
    const now = Date.now();
    const hit = marketCache.get(cacheKey);
    if (hit && now - hit.t < CACHE_TTL_MS) {
      return res.json(hit.data);
    }

    const map = {
      bitcoin:  "BTC/USDT",
      ethereum: "ETH/USDT",
      dogecoin: "DOGE/USDT",
    };
    const tdMap = await tdBatchPrices(Object.values(map));

    const pBTC  = Number(tdMap[map.bitcoin]);
    const pETH  = Number(tdMap[map.ethereum]);
    const pDOGE = Number(tdMap[map.dogecoin]);

    const payload = {
      bitcoin:  { usd: Number.isFinite(pBTC)  ? pBTC  : null },
      ethereum: { usd: Number.isFinite(pETH)  ? pETH  : null },
      dogecoin: { usd: Number.isFinite(pDOGE) ? pDOGE : null },
      updatedAt: Date.now()
    };

    marketCache.set(cacheKey, { t: now, data: payload });
    res.json(payload);
  } catch (e) {
    console.error("/crypto-prices (TD) error:", e?.message);
    res.status(502).json({ message: "Error obteniendo precios" });
  }
});


/* ============================
   Debug providers (útil para ver bloqueos)
   ============================ */
app.get("/debug/twelve", async (_req, res) => {
  try {
    const syms = ["BTC/USDT", "ETH/USDT", "EUR/USD", "USD/JPY"];
    const out = await tdBatchPrices(syms);
    res.json({
      apikey_preview: TWELVE_API_KEY ? (TWELVE_API_KEY.slice(0,3)+"..."+TWELVE_API_KEY.slice(-3)) : null,
      symbols: syms,
      prices: out
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/* ============================
   Health
   ============================ */
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

/* ============================
   Administración de Usuarios
   ============================ */
app.get("/usuarios", verifyToken, async (req, res) => {
  try {
    if (!["Dueño", "Gerente", "Trabajador"].includes(req.user.rol))
      return res.status(403).json({ message: "No autorizado" });
    const rows = await User.find({}, "_id nombre email rol").lean();
    const users = rows.map((u) => ({
      id: u._id.toString(),
      nombre: u.nombre,
      email: u.email,
      rol: u.rol,
    }));
    res.json(users);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al obtener usuarios" });
  }
});

app.put("/usuarios/:id/rol", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rol } = req.body;
    if (req.user.rol !== "Dueño") return res.status(403).json({ message: "No autorizado" });
    if (!mongoose.Types.ObjectId.isValid(id))
      return res.status(400).json({ message: "ID inválido" });
    const ROLES = ["Dueño", "Gerente", "Trabajador", "Usuario"];
    if (!ROLES.includes(rol)) return res.status(400).json({ message: "Rol inválido" });
    await User.findByIdAndUpdate(id, { rol });
    res.json({ message: "Rol actualizado correctamente" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al cambiar rol" });
  }
});

app.delete("/usuarios/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.rol !== "Dueño") return res.status(403).json({ message: "No autorizado" });
    if (!mongoose.Types.ObjectId.isValid(id))
      return res.status(400).json({ message: "ID inválido" });
    if (req.user.id === id)
      return res.status(400).json({ message: "No puedes eliminar tu propio usuario" });
    await User.findByIdAndDelete(id);
    res.json({ message: "Usuario eliminado" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Error al eliminar usuario" });
  }
});

/* ============================
   Arranque del servidor
   ============================ */
const PORT = process.env.PORT || 3301;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));

