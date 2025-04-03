const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const express = require("express");
const db = require("better-sqlite3")("note-app.db");

const app = express();
const port = 5030;

app.use(cookieParser());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));


// global middleware
app.use((req, res, next) => {
    res.locals.validationError = [];

    // verify the jwt cookie
    try {
        const decoded = jwt.verify(req.cookies.authentication,process.env.JWT_SECRET);
        console.log(decoded);
        req.authenticationToken = decoded;
    } catch (error) {
        req.authenticationToken = false;
    }

    res.locals.authenticationToken = req.authenticationToken;
    next();
});

app.get("/", (req, res) => {
    res.render("homePage");
});

app.get("/login", (req, res) => {
    res.render("loginPage");
});

app.post("/register", async (req, res) => {
    const validationError = [];

    if (typeof req.body.username !== "string") {
        req.body.username = "";
    }
    if (typeof req.body.password !== "string") {
        req.body.password = "";
    }

    proccessed_username = req.body.username.trim();

    if (!proccessed_username)
        validationError.push("You must provide a username");

    if (proccessed_username && proccessed_username.length < 3)
        validationError.push("Username must be at least 3 characters");

    if (proccessed_username && proccessed_username.length > 12)
        validationError.push("Username cannot exceed 12 characters");

    if (proccessed_username && !proccessed_username.match(/^[a-zA-Z0-9]+$/))
        validationError.push("Username can only contain letters and numbers");

    // Password validation
    proccessed_password = req.body.password;
    if (!proccessed_password)
        validationError.push("You must provide a password");

    if (proccessed_password && proccessed_password.length < 8)
        validationError.push("Password must be at least 8 characters");

    if (proccessed_password && proccessed_password.length > 64)
        validationError.push("Password cannot exceed 64 characters");

    if (validationError.length) {
        return res.render("homePage", { validationError });
    } else {
        // hash the password
        const salt = await bcrypt.genSalt(10);
        const hash_password = await bcrypt.hash(proccessed_password, salt);

        // query
        const insertUser = db.prepare(
            `INSERT INTO "user"(username, password) VALUES (? , ?)`
        );
        const insertedUser = insertUser.run(proccessed_username, hash_password);

        const selectUserId = db.prepare(`
            SELECT * FROM "user" WHERE id = ?`);
        const registeredUser = selectUserId.get(insertedUser.lastInsertRowid);

        // cookie handling
        const userToken = jwt.sign(
            {
                id: registeredUser.id,
                username: registeredUser.username,
            },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );

        res.cookie("authentication", userToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24,
        });

        res.send("Thank you for filling the forms");
    }
});

const createTableUser = db.prepare(`
    CREATE TABLE IF NOT EXISTS user(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL)`);

createTableUser.run();

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
