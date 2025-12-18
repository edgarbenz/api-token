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
//* Lo ideal es no meter datos sensibles aquí, solo lo mínimo necesario.
//*
//* // Crear un token con expiración de 1 hora
//* const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });
//* //* { expiresIn: '15m' } Define que el token expira en 15 minutos. 
// * → Después de ese tiempo, el cliente necesitará un refresh token o volver a iniciar sesión.
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
};//* sE RECOMIENDA NO PASAR PASSWORDS , SOLO USER O EMAIL

//* 🔹 Almacenamiento temporal de refresh tokens (en producción usar DB)
let refreshTokens = [];

//* Función para generar tokens
function generateAccessToken(user) {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '15m' }); //* Crea un JSON Web Token
} //* jwt.sign(...) Es la función de la librería jsonwebtoken que crea un JSON Web Token.
//* user Es el payload del token, normalmente un objeto con información del usuario (ej. id, username, role). ⚠️ Lo ideal es no meter datos sensibles aquí, solo lo mínimo necesario.
//* ACCESS_TOKEN_SECRET Es la clave secreta que usas para firmar el token. → Solo el servidor debe conocerla, porque garantiza que el token no pueda ser falsificado.
//* { expiresIn: '15m' } Define que el token expira en 15 minutos. → Después de ese tiempo, el cliente necesitará un refresh token o volver a iniciar sesión.

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: '7d' }); // 7 días
  refreshTokens.push(refreshToken); //* Guarda el refresh token en un arreglo en memoria (refreshTokens).
//*Esto sirve para llevar un control de los tokens válidos.
//*⚠️ En producción lo recomendable es usar una base de datos para poder invalidar tokens cuando el usuario cierre sesión o se detecte actividad sospechosa.
  return refreshToken;
} //* Usa la librería jsonwebtoken (jwt.sign) para firmar un token.
//* El payload es el objeto user (ej. { id: 123, email: "test@demo.com" }).
//* Se firma con la clave secreta REFRESH_TOKEN_SECRET.
//* Tiene una expiración de 7 días.

//* 🚀 Conclusión
//* El refresh token NO se genera automáticamente cada vez que expira el access token.
//* Se genera solo en el login.
//* Mientras el usuario esté conectado y tenga un refresh token válido, puede seguir renovando su access token.
//* Si se desconecta (logout) o el refresh token expira, ya no podrá renovar y tendrá que iniciar sesión de nuevo.

//* Ruta del Login
app.post('/login', (req, res) => {
  const { email, password } = req.body; //* recibe las credenciales del cliente con las que se logeo desde la app

  //* Primero checa si el email o password no existe responde con un 400 Bad Request
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  //* Si el email no coincide con ninguno de la BD responde con 401 Usuario No Encontrado
  if (email !== userDB.email) return res.status(401).json({ error: 'Usuario no encontrado' });

  //*compareSync es como un IF checa el password de texto del cliente contra los password encriptados validos de la BD
  const validPassword = bcrypt.compareSync(password, userDB.passwordHash);
  if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

  const user = { email };
  //* esa es una abreviatura de :
  //* const user = {
  //*   email: email
  //* };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.json({ accessToken, refreshToken });
});//* Regresa el accessToken y refreshToken al cliente si las credenciales son correctas

//* VOY AQUI
// 🔹 Ruta para renovar access token apartir de un refresh token  7  

//* El endpoint /token permite que el cliente obtenga un nuevo access token sin necesidad de volver a iniciar sesión, siempre que tenga un refresh token válido.
app.post('/token', (req, res) => { //* Esta función define un endpoint POST en Express (/token) 
//* que sirve para generar un nuevo access token A PARTIR DE UN refresh token. 
  const { token } = req.body; //* 1. Recepción del refresh token
                              //* Se espera que el cliente envíe un objeto JSON en el cuerpo
                              //*  de la petición con la propiedad token.
                              //* Ejemplo:
                              //* Con un json asi:   { "token": "refreshTokenEjemplo123" }
  if (!refreshTokens.includes(token)) return res.status(403).json({ error: 'Refresh token inválido' });
                              //* 2. Validación inicial
                              //* Si no se envía ningún token → responde con 401 Unauthorized:
                              //* Con un json asi:   { "error": "Refresh token requerido" }
  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Refresh token expirado o inválido' });
                              //* Si el token no está en la lista refreshTokens 
                              //* (es decir, no fue emitido previamente o ya fue invalidado) → 
                              //* responde con 403 Forbidden:
                              //* Con un json asi:
                              //* { "error": "Refresh token inválido" }

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

