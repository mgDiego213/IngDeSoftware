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

// ===== MongoDB =====
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Conexión exitosa a MongoDB Atlas"))
  .catch((err) => console.error("Error al conectar a MongoDB:", err));

// ===== Modelo de Usuario =====
const userSchema = new mongoose.Schema(
  {
    nombre:  { type: String, required: true },
    email:   { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:{ type: String, required: true },
    rol:     { type: String, default: "Usuario" },

    // Recuperación de contraseña
    resetPasswordTokenHash: { type: String, default: null },
    resetPasswordExpires:   { type: Date,   default: null },
  },
  { timestamps: true }
);
userSchema.index({ email: 1 }, { unique: true });
const User = mongoose.model("User", userSchema);

// ===== Middleware de Auth =====
function verifyToken(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.split(" ")[1] : auth;
    if (!token) return res.status(401).json({ message: "No autorizado" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, rol, iat, exp }
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}

// ===== Estáticos (sirve archivos desde la raíz) =====
const ROOT_DIR = __dirname;
app.use(express.static(ROOT_DIR));
app.get("/", (_req, res) => res.sendFile(path.join(ROOT_DIR, "index.html")));
app.get("/Inicio.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Inicio.html")));
app.get("/Mercados.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Mercados.html")));
app.get("/Administracion.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Administracion.html")));
app.get("/reset.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "reset.html"))); // <- NUEVA página

// Healthcheck para Render
app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

// ===== Nodemailer (Brevo por ENV) =====
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,                 // p.ej. smtp-relay.brevo.com
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === "true",  // true si usas 465
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

// ===== Rutas existentes =====
app.post("/register", async (req, res) => {
  const { nombre, email, password } = req.body;
  if (!nombre || !email || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "El usuario ya existe" });
    const hashed = bcrypt.hashSync(password, 10);
    const nuevo = await User.create({ nombre, email, password: hashed, rol: "Usuario" });
    return res.status(201).json({ message: "Usuario registrado correctamente", id: nuevo._id });
  } catch (err) {
    if (err?.code === 11000) return res.status(400).json({ message: "El usuario ya existe" });
    console.error("Error al registrar usuario:", err);
    return res.status(500).json({ message: "Error al registrar usuario" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Faltan datos en la solicitud" });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Usuario no encontrado" });
    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.status(400).json({ message: "Contraseña incorrecta" });
    const token = jwt.sign({ id: user._id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return res.json({ token, rol: user.rol, userId: user._id });
  } catch (err) {
    console.error("Error en login:", err);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.get("/usuarios", verifyToken, async (_req, res) => {
  try {
    const users = await User.find({}, "nombre email rol");
    return res.json(users);
  } catch (err) {
    console.error("Error al obtener usuarios:", err);
    return res.status(500).json({ message: "Error al obtener usuarios" });
  }
});

app.put("/usuarios/:id/rol", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  try {
    await User.findByIdAndUpdate(id, { rol });
    return res.json({ message: "Rol actualizado correctamente" });
  } catch (err) {
    console.error("Error al cambiar rol:", err);
    return res.status(500).json({ message: "Error al cambiar rol" });
  }
});

app.delete("/usuarios/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    await User.findByIdAndDelete(id);
    return res.json({ message: "Usuario eliminado correctamente" });
  } catch (err) {
    console.error("Error al eliminar usuario:", err);
    return res.status(500).json({ message: "Error al eliminar usuario" });
  }
});

app.get("/crypto-prices", async (_req, res) => {
  try {
    const response = await axios.get("https://api.coingecko.com/api/v3/simple/price", {
      params: { ids: "bitcoin,ethereum,dogecoin", vs_currencies: "usd" },
    });
    return res.json(response.data);
  } catch (error) {
    console.error("Error obteniendo precios:", error);
    return res.status(500).json({ message: "Error en el servidor al obtener precios" });
  }
});

app.post("/validate-token", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.split(" ")[1] : auth;
  if (!token) return res.status(401).json({ message: "No autorizado" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido o expirado" });
    return res.status(200).json({ message: "Token válido", user: decoded });
  });
});

// ===== Recuperación de contraseña =====

// 1) Solicitar link de reset (respuesta genérica para no filtrar emails)
app.post("/auth/request-password-reset", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ message: "Email requerido" });

  const genericMsg = "Si el correo existe, te enviaremos un enlace para restablecer.";
  try {
    const user = await User.findOne({ email }).select("_id email");
    if (!user) return res.json({ message: genericMsg });

    const tokenPlain = crypto.randomBytes(32).toString("hex");
    const tokenHash  = crypto.createHash("sha256").update(tokenPlain).digest("hex");
    const expires    = new Date(Date.now() + 15 * 60 * 1000);

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpires   = expires;
    await user.save();

    const resetLink = `${CLIENT_URL}/reset.html?token=${tokenPlain}&email=${encodeURIComponent(email)}`;

    await transporter.sendMail({
      from: process.env.MAIL_FROM || '"OrumGS" <no-reply@tu-dominio.com>',
      to: email,
      subject: "Restablecer tu contraseña",
      html: `
        <p>Hola,</p>
        <p>Solicitaste restablecer tu contraseña. Este enlace expira en 15 minutos:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>Si no fuiste tú, ignora este mensaje.</p>
      `,
    });

    return res.json({ message: genericMsg });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Error enviando el enlace de recuperación" });
  }
});

// 2) Aplicar nueva contraseña
app.post("/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  if (!email || !token || !newPassword) {
    return res.status(400).json({ message: "Datos incompletos" });
  }
  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      email,
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    }).select("_id password resetPasswordTokenHash resetPasswordExpires");

    if (!user) return res.status(400).json({ message: "Token inválido o expirado" });
    if (newPassword.length < 8) {
      return res.status(400).json({ message: "La contraseña debe tener al menos 8 caracteres." });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    user.password = hash;
    user.resetPasswordTokenHash = null;
    user.resetPasswordExpires = null;
    await user.save();

    return res.json({ message: "Contraseña actualizada. Ya puedes iniciar sesión." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Error al restablecer la contraseña" });
  }
});

// ===== Servidor =====
const PORT = process.env.PORT || 3301;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
