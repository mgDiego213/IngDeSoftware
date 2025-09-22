// ------------------------
// server.js (OrumGS)
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
  // CRYPTO (BINANCE · USDT)
  { key:"BTCUSDT", type:"crypto", label:"BTCUSDT (Bitcoin)",        tv_symbol:"BINANCE:BTCUSDT", cg_id:"bitcoin" },
  { key:"ETHUSDT", type:"crypto", label:"ETHUSDT (Ethereum)",       tv_symbol:"BINANCE:ETHUSDT", cg_id:"ethereum" },
  { key:"BNBUSDT", type:"crypto", label:"BNBUSDT (BNB)",            tv_symbol:"BINANCE:BNBUSDT", cg_id:"binancecoin" },
  { key:"SOLUSDT", type:"crypto", label:"SOLUSDT (Solana)",         tv_symbol:"BINANCE:SOLUSDT", cg_id:"solana" },
  { key:"XRPUSDT", type:"crypto", label:"XRPUSDT (XRP)",            tv_symbol:"BINANCE:XRPUSDT", cg_id:"ripple" },
  { key:"ADAUSDT", type:"crypto", label:"ADAUSDT (Cardano)",        tv_symbol:"BINANCE:ADAUSDT", cg_id:"cardano" },
  { key:"DOGEUSDT",type:"crypto", label:"DOGEUSDT (Dogecoin)",      tv_symbol:"BINANCE:DOGEUSDT",cg_id:"dogecoin" },
  { key:"AVAXUSDT",type:"crypto", label:"AVAXUSDT (Avalanche)",     tv_symbol:"BINANCE:AVAXUSDT",cg_id:"avalanche-2" },
  { key:"TRXUSDT", type:"crypto", label:"TRXUSDT (TRON)",           tv_symbol:"BINANCE:TRXUSDT", cg_id:"tron" },
  { key:"TONUSDT", type:"crypto", label:"TONUSDT (TON)",            tv_symbol:"BINANCE:TONUSDT", cg_id:"the-open-network" },
  { key:"LINKUSDT",type:"crypto", label:"LINKUSDT (Chainlink)",     tv_symbol:"BINANCE:LINKUSDT",cg_id:"chainlink" },
  { key:"MATICUSDT",type:"crypto",label:"MATICUSDT (Polygon)",      tv_symbol:"BINANCE:MATICUSDT",cg_id:"matic-network" },
  { key:"DOTUSDT", type:"crypto", label:"DOTUSDT (Polkadot)",       tv_symbol:"BINANCE:DOTUSDT", cg_id:"polkadot" },
  { key:"LTCUSDT", type:"crypto", label:"LTCUSDT (Litecoin)",       tv_symbol:"BINANCE:LTCUSDT", cg_id:"litecoin" },
  { key:"BCHUSDT", type:"crypto", label:"BCHUSDT (Bitcoin Cash)",   tv_symbol:"BINANCE:BCHUSDT", cg_id:"bitcoin-cash" },
  { key:"ATOMUSDT",type:"crypto", label:"ATOMUSDT (Cosmos)",        tv_symbol:"BINANCE:ATOMUSDT",cg_id:"cosmos" },
  { key:"ARBUSDT", type:"crypto", label:"ARBUSDT (Arbitrum)",       tv_symbol:"BINANCE:ARBUSDT", cg_id:"arbitrum" },
  { key:"OPUSDT",  type:"crypto", label:"OPUSDT (Optimism)",        tv_symbol:"BINANCE:OPUSDT",  cg_id:"optimism" },

  // FOREX (usa OANDA por defecto; puedes cambiar a "FX" abajo)
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
   Micro-cache en memoria
   ============================ */
const marketCache = new Map(); // "keys=BTCUSDT,EURUSD" -> { t, data }
const CACHE_TTL_MS = parseInt(process.env.MARKET_CACHE_TTL_MS || "10000", 10);

/* ============================
   Helpers externos
   ============================ */
// Precio spot desde Binance "BTCUSDT", "ETHUSDT", ...
async function getBinancePrice(symbol) {
  try {
    const url = `https://api.binance.com/api/v3/ticker/price?symbol=${encodeURIComponent(symbol)}`;
    const { data } = await axios.get(url, { timeout: 8000 });
    const p = parseFloat(data?.price);
    return Number.isFinite(p) ? p : null;
  } catch (e) {
    console.error("Binance price error", symbol, e?.response?.status || e.message);
    return null;
  }
}

// Fallback para FOREX usando exchangerate.host (USD por 1 unidad del par)
async function getFX_USD(pair) {
  try {
    const base = pair.slice(0,3);
    const quote = pair.slice(3,6);

    if (quote === 'USD') {
      const { data } = await axios.get(
        `https://api.exchangerate.host/latest?base=${base}&symbols=USD`,
        { timeout: 10000 }
      );
      const v = data?.rates?.USD;
      return Number.isFinite(v) ? v : null;
    }
    if (base === 'USD') {
      const { data } = await axios.get(
        `https://api.exchangerate.host/latest?base=USD&symbols=${quote}`,
        { timeout: 10000 }
      );
      const q = data?.rates?.[quote];
      return Number.isFinite(q) ? (1 / q) : null;
    }
    return null;
  } catch {
    return null;
  }
}

/* ============================
   FINNHUB HELPERS
   ============================ */
const FINNHUB_API_KEY =
  process.env.FINNHUB_API_KEY ||
  "d38s4c1r01qthpo1867gd38s4c1r01qthpo18680";
const FINNHUB_HTTP_TIMEOUT = 15000;

/** Último close de 1m para CRYPTO en Finnhub. Ej: "BINANCE:BTCUSDT" */
async function finnhubCryptoLast(symbolFinnhub) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const from = now - 300; // 5 minutos
    const url = `https://finnhub.io/api/v1/crypto/candle?symbol=${encodeURIComponent(
      symbolFinnhub
    )}&resolution=1&from=${from}&to=${now}&token=${FINNHUB_API_KEY}`;
    const { data } = await axios.get(url, { timeout: FINNHUB_HTTP_TIMEOUT });
    if (data?.s !== "ok" || !Array.isArray(data?.c) || data.c.length === 0) return null;
    const last = Number(data.c[data.c.length - 1]);
    return Number.isFinite(last) ? last : null;
  } catch (err) {
    console.error("[finnhubCryptoLast]", symbolFinnhub, err?.response?.status || err?.code || err?.message);
    return null;
  }
}

/** Último close de 1m para FOREX en Finnhub. Por defecto OANDA:BASE_QUOTE */
async function finnhubForexLast(base, quote, provider = "OANDA") {
  try {
    const symbol = provider === "OANDA" ? `OANDA:${base}_${quote}` : `FX:${base}${quote}`;
    const now = Math.floor(Date.now() / 1000);
    const from = now - 300;
    const url = `https://finnhub.io/api/v1/forex/candle?symbol=${encodeURIComponent(
      symbol
    )}&resolution=1&from=${from}&to=${now}&token=${FINNHUB_API_KEY}`;
    const { data } = await axios.get(url, { timeout: FINNHUB_HTTP_TIMEOUT });
    if (data?.s !== "ok" || !Array.isArray(data?.c) || data.c.length === 0) return null;
    const last = Number(data.c[data.c.length - 1]);
    return Number.isFinite(last) ? last : null;
  } catch (err) {
    console.error("[finnhubForexLast]", base, quote, err?.response?.status || err?.code || err?.message);
    return null;
  }
}

/* ============================
   Fallback adicional: CoinGecko (batch)
   ============================ */
// Recibe array de ids de CoinGecko -> devuelve { id: priceUSD }
async function getCoinGeckoBatch(cgIds) {
  try {
    if (!Array.isArray(cgIds) || cgIds.length === 0) return {};
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(
      cgIds.join(",")
    )}&vs_currencies=usd`;
    const { data } = await axios.get(url, { timeout: 12000 });
    const out = {};
    for (const id of cgIds) {
      const v = data?.[id]?.usd;
      if (typeof v === "number" && Number.isFinite(v)) out[id] = v;
    }
    return out;
  } catch (e) {
    console.error("CoinGecko batch error:", e?.response?.status || e?.message);
    return {};
  }
}

/* ============================
   Precios unificados
   ============================ */
/**
 * GET /market-prices?keys=BTCUSDT,EURUSD
 * Respuesta: { items: [{ key, type, label, price_usd }] }
 * - CRYPTO: Finnhub (BINANCE:<PAR>) -> Binance -> CoinGecko
 * - FOREX : Finnhub (OANDA:BASE_QUOTE) -> exchangerate.host
 */
app.get("/market-prices", async (req, res) => {
  try {
    const keys = String(req.query.keys || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (keys.length === 0) return res.json({ items: [] });

    // micro-cache
    const cacheKey = "keys=" + keys.join(",");
    const hit = marketCache.get(cacheKey);
    const now = Date.now();
    if (hit && now - hit.t < CACHE_TTL_MS) {
      return res.json(hit.data);
    }

    // Normaliza a TOP30
    const reqItems = keys.map((k) => TOP30.find((x) => x.key === k)).filter(Boolean);
    const cryptoItems = reqItems.filter((x) => x.type === "crypto");
    const forexItems  = reqItems.filter((x) => x.type === "forex");

    // --- CRYPTO: Finnhub -> Binance -> CoinGecko ---
    const cryptoMap = {};
    const missingCgIds = []; // ids CG que faltan
    const keyToCgId = {};
    await Promise.all(
      cryptoItems.map(async (c) => {
        const sym = `BINANCE:${c.key}`;
        let p = await finnhubCryptoLast(sym);
        if (p == null) p = await getBinancePrice(c.key);
        if (p == null && c.cg_id) {
          missingCgIds.push(c.cg_id);
          keyToCgId[c.key] = c.cg_id;
        }
        cryptoMap[c.key] = p;
      })
    );
    if (missingCgIds.length) {
      const cg = await getCoinGeckoBatch(missingCgIds);
      for (const k of Object.keys(keyToCgId)) {
        const id = keyToCgId[k];
        if (cryptoMap[k] == null && typeof cg[id] === "number") cryptoMap[k] = cg[id];
      }
    }

    // --- FOREX: Finnhub -> exchangerate.host ---
    const fxMap = {};
    await Promise.all(
      forexItems.map(async (f) => {
        const base = f.fx?.base, quote = f.fx?.quote;
        let p = null;
        if (base && quote) {
          p = await finnhubForexLast(base, quote, "OANDA"); // cambia a "FX" si prefieres FX:EURUSD
          if (p == null) p = await getFX_USD(`${base}${quote}`);
        }
        fxMap[f.key] = p;
      })
    );

    // Orden solicitado
    const items = reqItems.map((it) => ({
      key: it.key,
      type: it.type,
      label: it.label,
      price_usd:
        it.type === "crypto"
          ? cryptoMap[it.key] ?? null
          : it.type === "forex"
          ? fxMap[it.key] ?? null
          : null,
    }));

    const payload = { items };
    marketCache.set(cacheKey, { t: now, data: payload });
    res.json(payload);
  } catch (e) {
    console.error("market-prices error:", e?.message || e);
    res.status(502).json({ items: [] });
  }
});

/**
 * GET /crypto-prices
 * - Mantiene el "shape" que usa tu front { bitcoin:{usd}, ethereum:{usd}, dogecoin:{usd} }
 * - Soporta ?ids=bitcoin,ethereum,dogecoin
 * - Fuente: Finnhub -> Binance -> CoinGecko
 */
app.get("/crypto-prices", async (req, res) => {
  try {
    const idsParam = (req.query.ids || "bitcoin,ethereum,dogecoin")
      .toString()
      .trim()
      .toLowerCase();

    const ids = idsParam.split(",").map((s) => s.trim()).filter(Boolean);

    const idToSymbol = {
      bitcoin:  "BINANCE:BTCUSDT",
      ethereum: "BINANCE:ETHUSDT",
      dogecoin: "BINANCE:DOGEUSDT",
    };
    const idToPair = {
      bitcoin:  "BTCUSDT",
      ethereum: "ETHUSDT",
      dogecoin: "DOGEUSDT",
    };

    const result = {};
    const missing = []; // ids que faltan para pedir a CoinGecko

    await Promise.all(
      ids.map(async (id) => {
        const sym = idToSymbol[id];
        const pair = idToPair[id];
        let p = null;

        if (sym) p = await finnhubCryptoLast(sym);
        if (p == null && pair) p = await getBinancePrice(pair);

        if (p == null) missing.push(id);
        result[id] = { usd: p ?? null };
      })
    );

    if (missing.length) {
      const cg = await getCoinGeckoBatch(missing);
      for (const id of missing) {
        if (typeof cg[id] === "number") result[id].usd = cg[id];
      }
    }

    res.json(result);
  } catch (e) {
    console.error("Error /crypto-prices:", e?.message);
    res.status(502).json({ message: "Error obteniendo precios" });
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
