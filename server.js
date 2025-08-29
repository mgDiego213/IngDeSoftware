require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ===== MongoDB =====
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Conexión exitosa a MongoDB Atlas"))
  .catch((err) => console.error("Error al conectar a MongoDB:", err));

// ===== Modelo =====
const userSchema = new mongoose.Schema(
  {
    nombre:  { type: String, required: true },
    email:   { type: String, required: true, unique: true },
    password:{ type: String, required: true },
    rol:     { type: String, default: "Usuario" },
  },
  { timestamps: true }
);
userSchema.index({ email: 1 }, { unique: true });
const User = mongoose.model("User", userSchema);

// ===== Auth middleware =====
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

// ===== Archivos estáticos (HTML/CSS/JS en la RAÍZ) =====
const ROOT_DIR = __dirname;
app.use(express.static(ROOT_DIR));

// Rutas públicas a HTML
app.get("/", (_req, res) => res.sendFile(path.join(ROOT_DIR, "index.html")));
app.get("/Inicio.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Inicio.html")));
app.get("/Mercados.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Mercados.html")));
app.get("/Administracion.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "Administracion.html")));

// (Opcional) healthcheck para Render
app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

// ====== APIs ======
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
      params: { ids: "bitcoin,ethereum,dogecoin", vs_currencies: "usd" }
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

// ===== Server =====
const PORT = process.env.PORT || 3301;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
