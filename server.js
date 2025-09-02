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

// ===== DB =====
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/orumgs";
mongoose.set("strictQuery", true);
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch((e) => {
    console.error("Error conectando a MongoDB:", e.message);
  });

// ===== Modelo =====
const userSchema = new mongoose.Schema(
  {
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    rol: { type: String, default: "Usuario" },

    // Recuperación de contraseña
    resetPasswordTokenHash: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null },
  },
  { timestamps: true }
);
// Nota: NO declaramos schema.index({ email: 1 }) para evitar el warning de índice duplicado
const User = mongoose.model("User", userSchema);

// ===== Util =====
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), rol: user.rol, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Middleware de auth
function verifyToken(req, res, next) {
  try {
    const auth = req.headers["authorization"] || req.headers["Authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
    if (!token) return res.status(401).json({ message: "No autorizado" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, rol, email }
    return next();
  } catch (e) {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}

// ===== Estáticos =====
const ROOT_DIR = __dirname;
app.use(express.static(ROOT_DIR));
app.get("/", (_req, res) => res.sendFile(path.join(ROOT_DIR, "index.html")));
["/Inicio.html", "/Mercados.html", "/Administracion.html", "/reset.html"].forEach((route) => {
  app.get(route, (_req, res) => res.sendFile(path.join(ROOT_DIR, route.replace("/", ""))));
});

// ===== Auth =====
app.post("/register", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) {
      return res.status(400).json({ message: "Faltan campos" });
    }
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "El correo ya está registrado" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ nombre, email, password: hash, rol: "Usuario" });

    return res.json({ message: "Usuario registrado", id: user._id.toString() });
  } catch (e) {
    console.error("Error en register:", e);
    return res.status(500).json({ message: "Error al registrar" });
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
    return res.json({ token, rol: user.rol, userId: user._id.toString() });
  } catch (e) {
    console.error("Error en login:", e);
    return res.status(500).json({ message: "Error en login" });
  }
});

app.post("/validate-token", (req, res) => {
  try {
    const auth = req.headers["authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
    if (!token) return res.status(401).json({ message: "No autorizado" });
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ ok: true, user: decoded });
  } catch (e) {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
});

// ===== Datos de mercado (CoinGecko) =====
app.get("/crypto-prices", async (_req, res) => {
  try {
    const url =
      "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,dogecoin&vs_currencies=usd";
    const { data } = await axios.get(url, { timeout: 10000, headers: { "x-cg-demo-api-key": "" } });
    return res.json(data);
  } catch (e) {
    console.error("Error obteniendo precios:", e?.response?.status || e.message);
    return res.status(502).json({ message: "Error obteniendo precios" });
  }
});

// ===== Listado de usuarios (Dueño/Gerente/Trabajador → solo lectura para Trabajador) =====
app.get("/usuarios", verifyToken, async (req, res) => {
  try {
    if (!["Dueño", "Gerente", "Trabajador"].includes(req.user.rol)) {
      return res.status(403).json({ message: "No autorizado" });
    }
    const rows = await User.find({}, "_id nombre email rol").lean();
    const users = rows.map((u) => ({
      id: u._id.toString(),
      nombre: u.nombre,
      email: u.email,
      rol: u.rol,
    }));
    return res.json(users);
  } catch (e) {
    console.error("Error al obtener usuarios:", e);
    return res.status(500).json({ message: "Error al obtener usuarios" });
  }
});

// ===== Cambiar rol (Solo Dueño) =====
app.put("/usuarios/:id/rol", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rol } = req.body;
    if (req.user.rol !== "Dueño") {
      return res.status(403).json({ message: "No autorizado" });
    }
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID inválido" });
    }
    const ROLES = ["Dueño", "Gerente", "Trabajador", "Usuario"];
    if (!ROLES.includes(rol)) {
      return res.status(400).json({ message: "Rol inválido" });
    }
    await User.findByIdAndUpdate(id, { rol });
    return res.json({ message: "Rol actualizado correctamente" });
  } catch (e) {
    console.error("Error al cambiar rol:", e);
    return res.status(500).json({ message: "Error al cambiar rol" });
  }
});

// ===== Eliminar usuario (Solo Dueño, no puede eliminarse a sí mismo) =====
app.delete("/usuarios/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.rol !== "Dueño") {
      return res.status(403).json({ message: "No autorizado" });
    }
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID inválido" });
    }
    if (req.user.id === id) {
      return res.status(400).json({ message: "No puedes eliminar tu propio usuario" });
    }
    await User.findByIdAndDelete(id);
    return res.json({ message: "Usuario eliminado" });
  } catch (e) {
    console.error("Error al eliminar usuario:", e);
    return res.status(500).json({ message: "Error al eliminar usuario" });
  }
});

// ===== Password reset (Brevo + token hasheado) =====
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
    // Para evitar enumeración de usuarios: respondemos similar aunque no exista
    if (!user) return res.json({ message: "Si el correo existe, te enviaremos un enlace" });

    const tokenPlain = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(tokenPlain).digest("hex");

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 1000 * 60 * 60); // 1 hora
    await user.save();

    const resetLink = `${CLIENT_URL ? CLIENT_URL.replace(/\/+$/, "") : ""}/reset.html?token=${tokenPlain}&email=${encodeURIComponent(
      email
    )}`;

    await transporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "Restablecer contraseña",
      html: `
        <p>Solicitaste restablecer tu contraseña.</p>
        <p>Haz clic en el siguiente enlace (válido por 1 hora):</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>Si no fuiste tú, ignora este mensaje.</p>
      `,
    });

    return res.json({ message: "Si el correo existe, te enviaremos un enlace" });
  } catch (e) {
    console.error("Error en request-password-reset:", e);
    return res.status(500).json({ message: "Error al solicitar restablecimiento" });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, email, password } = req.body;
    if (!token || !email || !password) {
      return res.status(400).json({ message: "Datos incompletos" });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      email,
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) {
      return res.status(400).json({ message: "Token inválido o expirado" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordTokenHash = null;
    user.resetPasswordExpires = null;
    await user.save();

    return res.json({ message: "Contraseña actualizada. Ya puedes iniciar sesión." });
  } catch (e) {
    console.error("Error en reset-password:", e);
    return res.status(500).json({ message: "Error al restablecer la contraseña" });
  }
});

// ===== Servidor =====
const PORT = process.env.PORT || 3301;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));