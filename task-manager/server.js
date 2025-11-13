
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-15min-key';
const TOKEN_EXPIRES_IN = '15m';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Ошибка БД:', err.message);
  } else {
    console.log('✅ SQLite готов. Сервер запущен на http://localhost:3000');
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);
  }
});


app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashed], function(err) {
      if (err && err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Email уже используется' });
      }
      if (err) return res.status(500).json({ error: 'Ошибка регистрации' });
      res.json({ success: true, redirect: '/login.html' });
    });
  } catch {
    res.status(500).json({ error: 'Ошибка хеширования' });
  }
});


app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
    res.json({ success: true, token, redirect: '/index.html' });
  });
});


app.get('/api/protected', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Токен не предоставлен' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    res.json({ ok: true, user: decoded });
  } catch {
    res.status(401).json({ error: 'Токен недействителен или просрочен' });
  }
});

app.listen(PORT);