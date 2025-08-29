const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Función para generar un token JWT
const generarToken = (usuario) => {
    return jwt.sign(
        { id: usuario.id, email: usuario.email },
        process.env.JWT_SECRET,  // Clave secreta
        { expiresIn: '1h' }      // Expira en 1 hora
    );
};

module.exports = { generarToken };