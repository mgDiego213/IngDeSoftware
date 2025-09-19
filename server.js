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
   Top 30 Mixto (Cripto · Forex · Índices)
   ============================ */
const TOP30 = [
  // === CRYPTO (18) BINANCE · USDT
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

  // === FOREX (8)
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
const marketCache = new Map(); // "keys=BTCUSDT,SPX" -> { t, data }
const CACHE_TTL_MS = parseInt(process.env.MARKET_CACHE_TTL_MS || "10000", 10);

/* ============================
   Helpers externos
   ============================ */
// Precio spot desde Binance para "BTCUSDT", "ETHUSDT", ...
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

/* ============================
   Precios unificados
   ============================ */
/**
 * GET /market-prices?keys=BTCUSDT,EURUSD,SPX
 * Respuesta: { items: [{ key, type, label, price_usd }] }
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

    // Validar/ordenar contra TOP30
    const items = keys.map((k) => TOP30.find((x) => x.key === k)).filter(Boolean);

    // Agrupar
    const cryptoItems = items.filter((x) => x.type === "crypto");
    const forexList = items.filter((x) => x.type === "forex");
    const indexList = items.filter((x) => x.type === "index");

    // 1) Crypto via CoinGecko (fallback Binance)
    let cgPrices = {};
    try {
      const cryptoIds = cryptoItems.map((x) => x.cg_id);
      if (cryptoIds.length > 0) {
        const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(
          cryptoIds.join(",")
        )}&vs_currencies=usd`;
        const { data } = await axios.get(url, { timeout: 20000 });
        cgPrices = data || {};
      }
    } catch (e) {
      console.error("CoinGecko error:", e?.response?.status || e.message);
      cgPrices = {};
    }

    // Fallback a Binance para los cripto que vengan sin precio
    const binanceMap = {};
    const missingCryptoSymbols = cryptoItems
      .filter((c) => !(cgPrices[c.cg_id] && cgPrices[c.cg_id].usd != null))
      .map((c) => c.key);
    if (missingCryptoSymbols.length) {
      await Promise.all(
        missingCryptoSymbols.map((sym) =>
          getBinancePrice(sym).then((p) => {
            binanceMap[sym] = p;
          })
        )
      );
    }

    // 2) Forex via exchangerate.host
    async function fxRate(base, quote) {
      try {
        const u = `https://api.exchangerate.host/latest?base=${encodeURIComponent(
          base
        )}&symbols=${encodeURIComponent(quote)}`;
        const { data } = await axios.get(u, { timeout: 20000 });
        return data && data.rates ? data.rates[quote] : null;
      } catch (e) {
        console.error("FX error", base, quote, e?.response?.status || e.message);
        return null;
      }
    }
    const fxCache = {};
    for (const f of forexList) {
      const k = `${f.fx.base}_${f.fx.quote}`;
      if (!(k in fxCache)) fxCache[k] = await fxRate(f.fx.base, f.fx.quote);
    }

    // 3) Índices via Stooq (CSV, último close)
    let stooqMap = {};
    if (indexList.length > 0) {
      try {
        const codes = indexList.map((x) => x.stooq).join(",");
        const url = `https://stooq.com/q/l/?s=${encodeURIComponent(codes)}&i=d`;
        const { data } = await axios.get(url, { timeout: 20000, responseType: "text" });
        const lines = String(data || "").trim().split("\n").filter(Boolean);
        for (const line of lines.slice(1)) {
          const parts = line.split(",");
          const sym = parts[0]?.trim();
          const close = parseFloat(parts[6]);
          if (sym && Number.isFinite(close)) stooqMap[sym] = close;
        }
      } catch (e) {
        console.error("Stooq error:", e?.response?.status || e.message);
        stooqMap = {};
      }
    }

    // Respuesta en el mismo orden solicitado
    const out = items.map((it) => {
      let price = null;
      if (it.type === "crypto") {
        price = cgPrices[it.cg_id]?.usd ?? binanceMap[it.key] ?? null;
      } else if (it.type === "forex") {
        price = fxCache[`${it.fx.base}_${it.fx.quote}`] ?? null;
      } else if (it.type === "index") {
        price = stooqMap[it.stooq] ?? null;
      }
      return { key: it.key, type: it.type, label: it.label, price_usd: price };
    });

    const payload = { items: out };
    marketCache.set(cacheKey, { t: now, data: payload });
    res.json(payload);
  } catch (e) {
    console.error("market-prices fatal:", e?.message || e);
    res.status(502).json({ items: [] });
  }
});

/* ============================
   Compatibilidad y Health
   ============================ */
app.get("/crypto-prices", async (req, res) => {
  try {
    const idsParam = (req.query.ids || "bitcoin,ethereum,dogecoin")
      .toString()
      .trim()
      .toLowerCase();
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(
      idsParam
    )}&vs_currencies=usd`;
    const { data } = await axios.get(url, { timeout: 20000 });
    res.json(data);
  } catch (e) {
    console.error("Error precios CG:", e?.message);
    res.status(502).json({ message: "Error obteniendo precios" });
  }
});

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

