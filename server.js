require('dotenv').config(); // * Biblioteca dotenv que permite cargar automaticamente variables de entorno desde un archivo .env
const express = require('express');
const jwt = require('jsonwebtoken'); //* Importacion del modulo externo jsonwebtoketn y asignandolo a jwt, previamente instalado con "npm install jsonwebtoken"
//* A partir de ahí, puedes usar métodos como:
//* jwt.sign(payload, secret, options) → para crear un token.
//* jwt.verify(token, secret) → para validar un token.
//* jwt.decode(token) → para leer el contenido sin verificarlo.
//* Ejemplo:
//* const jwt = require('jsonwebtoken');
//* // Clave secreta para firmar el token
//* const secretKey = 'mi_clave_secreta';
//*
//* // Datos que quieres incluir en el token
//* const payload = { id: 1, usuario: 'admin' };
//*
//* // Crear un token con expiración de 1 hora
//* const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });
//* console.log('Token generado:', token);
//*
//* // Verificar y decodificar el token
//* try {
//*     const decoded = jwt.verify(token, secretKey);
//*     console.log('Token válido. Datos:', decoded);
//* } catch (err) {
//*     console.error('Token inválido o expirado:', err.message);
//* }
const bcrypt = require('bcryptjs'); //* Es para hashing (encriptar de forma irreversible) contraseñas y compararlas de forma segura
//* A partir de ahí, puedes usar sus métodos, como:
//* bcrypt.hash() → para cifrar (hashear) contraseñas.
//* bcrypt.compare() → para comparar una contraseña ingresada con un hash almacenado.
//* Ejemplo:
//* ¿Para qué se usa?
//*
//* Hashear contraseñas antes de guardarlas en una base de datos:
//* const hashedPassword = await bcrypt.hash('miContraseñaSegura', 10);
//* console.log(hashedPassword); // Ejemplo: $2a$10$EixZaYVK1fsbw1ZfbX3OXe...
//*
//* Comparar contraseñas ingresadas por el usuario con el hash almacenado:
//* const match = await bcrypt.compare('miContraseñaSegura', hashedPassword);
//* if (match) {
//*     console.log('Contraseña correcta');
//* } else {
//*     console.log('Contraseña incorrecta');
//* }
const cors = require('cors');
//* CORS es un mecanismo de seguridad implementado por los navegadores que controla qué dominios pueden hacer peticiones HTTP a tu servidor cuando el origen (dominio, protocolo o puerto) es diferente.
//* Ej: Tu API está en https://api.midominio.com
//* Tu frontend está en https://app.otrodominio.com
//* Sin CORS configurado, el navegador bloqueará la petición por seguridad.
// * Ejemplo: const express = require('express');
// *const cors = require('cors');
//* const app = express();
//* Habilitar CORS para todos los orígenes
//* app.use(cors());
//* Ruta de ejemplo
//* app.get('/api/data', (req, res) => {
//* res.json({ mensaje: 'CORS habilitado correctamente' });
//* });
//* app.listen(3000, () => {
//* console.log('Servidor escuchando en http://localhost:3000');
//* });
//* 📌 Configuración personalizada
//* Puedes restringir qué dominios tienen acceso:
//* app.use(cors({
//*   origin: 'https://midominio.com', // Solo este dominio puede acceder
//*   methods: ['GET', 'POST'],        // Métodos permitidos
//*   allowedHeaders: ['Content-Type', 'Authorization']
//* }));

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

const app = express();
app.use(cors());
app.use(express.json());
//* app.use(...): es una función de Express que sirve para registrar middlewares. Un middleware es básicamente una función que se ejecuta cada vez que llega una petición al servidor, antes de que se procese la respuesta.
//* express.json(): es un middleware incluido en Express que se encarga de leer el cuerpo (body) de las peticiones HTTP cuando vienen en formato JSON. Convierte ese contenido en un objeto JavaScript accesible desde req.body.
//* Si mandas un POST con este JSON:
//* {
//*   "nombre": "Edgar",
//*   "edad": 30
//* }
//* Gracias a express.json(), podrás acceder así:
//* app.post('/usuarios', (req, res) => {
//* console.log(req.body.nombre); // "Edgar"
//* console.log(req.body.edad);   // 30
//* });

// 🔹 Usuario de ejemplo (en producción usar base de datos)
// Aqui se deben guardar  TODOS los usuarios en un arreglo desde la BD
const userDB = {
  email: 'test@demo.com',
  passwordHash: bcrypt.hashSync('123456', 10) //el password 123456 se guarda pero encriptado
};

// 🔹 Almacenamiento temporal de refresh tokens (en producción usar DB)
let refreshTokens = [];

// Función para generar tokens
function generateAccessToken(user) {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '15m' }); // 15 minutos
} // regresa un token JKT codificado en Base64: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
// .eyJlbWFpbCI6InRlc3RAZGVtby5jb20iLCJpYXQiOjE3MzU5MjM2MDAsImV4cCI6MTczNTkyNDUwMH0
// .qd9Xz7lq2QkYw0vXzXzY7Qh7oX9vWmZsQk9lYzZkY2U
// contiene esto: 
// {
//   email: "test@demo.com",
//   iat: 1735923600,   // Tiempo exacto en que fue creado
//   exp: 1735924500    // expiration (timestamp)
// }

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: '7d' }); // 7 días
  refreshTokens.push(refreshToken); // en produccion usar BD
  return refreshToken;
} // Genera un token igual que el de arriba pero de larga duracion
// Es un token de larga duración que sirve para pedir nuevos access tokens sin que el usuario tenga que volver a iniciar sesión.
// Se usa cuando el access token (que dura poco, en tu caso 15 minutos) expira y el usuario sigue legeado.
// El refresh token se envía al servidor en la ruta /token, y si es válido, el servidor genera un nuevo access token.
// 🚀 Conclusión
// El refresh token NO se genera automáticamente cada vez que expira el access token.
// Se genera solo en el login.
// Mientras el usuario esté conectado y tenga un refresh token válido, puede seguir renovando su access token.
// Si se desconecta (logout) o el refresh token expira, ya no podrá renovar y tendrá que iniciar sesión de nuevo.

//Regresa el accessToken de 15 min y el Refresh Token de 7 dias en formato JSON
app.post('/login', (req, res) => {
  const { email, password } = req.body; // recibe las credenciales del cliente con las que se logeo desde la app

  // Primero checa si el email o password no existe responde con un 400 Bad Request
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  // Si el email no coincide con ninguno de la BD responde con 401 Usuario No Encontrado
  if (email !== userDB.email) return res.status(401).json({ error: 'Usuario no encontrado' });

  //compareSync es como un IF checa el password de texto del cliente contra los password encriptados validos de la BD
  const validPassword = bcrypt.compareSync(password, userDB.passwordHash);
  if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

  const user = { email };
  // esa es una abreviatura de :
  // const user = {
  //   email: email
  // };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.json({ accessToken, refreshToken });
});

// *VOY AQUI
// 🔹 Ruta para renovar access token
app.post('/token', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ error: 'Refresh token requerido' });
  if (!refreshTokens.includes(token)) return res.status(403).json({ error: 'Refresh token inválido' });

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Refresh token expirado o inválido' });
    const accessToken = generateAccessToken({ email: user.email });
    res.json({ accessToken });
  });
});

// 🔹 Logout (elimina refresh token)
app.post('/logout', (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(rt => rt !== token);
  res.json({ mensaje: 'Logout exitoso' });
});

// 🔹 Middleware para verificar access token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    req.user = user;
    next();
  });
}

// 🔹 Ruta protegida
app.get('/protegido', authenticateToken, (req, res) => {
  res.json({ mensaje: 'Acceso concedido', usuario: req.user });
});

// 🔹 Iniciar servidor
const PORT = 4000;
app.listen(PORT, () => console.log(`API escuchando en http://localhost:${PORT}`));

