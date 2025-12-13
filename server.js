const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // Замените на что-то безопасное

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public")); // Для HTML файлов

// Настройка подключения к MySQL
const db = mysql.createConnection({
    host: "db", // имя контейнера MySQL в Docker Compose
    user: "root",
    password: "rootpassword",
    database: "testdb",
});

db.connect((err) => {
    if (err) {
        console.error("Ошибка подключения к MySQL:", err);
        return;
    }
    console.log("Подключено к MySQL");
});

// Регистрация
app.post("/register", (req, res) => {
    const { username, email, password, role } = req.body;

    if (!["admin", "employee"].includes(role)) {
        return res.status(400).send("Неверная роль");
    }

    const sql = "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
    db.query(sql, [username, email, password, role], (err, result) => {
        if (err) return res.status(500).send("Ошибка базы данных");
        res.redirect("index.html");
    });
});

// Вход
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    db.query(sql, [email, password], (err, results) => {
        if (err) return res.status(500).send("Ошибка базы данных");
        if (results.length === 0) return res.status(401).send("Неверные данные");

        const token = jwt.sign(
            { id: results[0].id, role: results[0].role },
            SECRET_KEY,
            { expiresIn: "1h" }
        );
        res.cookie("token", token, { httpOnly: true });
        res.redirect("main.html");
    });
});

// Middleware для проверки токена
function authMiddleware(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send("Требуется авторизация");
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send("Неверный или просроченный токен");
    }
}

// Защищённый маршрут /main — ОСНОВНОЕ ИЗМЕНЕНИЕ
app.get("/main", authMiddleware, (req, res) => {
    res.sendFile(__dirname + "/public/main.html");
});

// Dashboard (оставлен как есть)
app.get("/dashboard", authMiddleware, (req, res) => {
    res.send(`Привет, пользователь с ID ${req.user.id} и ролью ${req.user.role}`);
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});