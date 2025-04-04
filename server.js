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
    res.locals.registrationValidationError = [];
    res.locals.loginValidationError = [];

    // verify the jwt cookie
    try {
        const decoded = jwt.verify(
            req.cookies.authentication,
            process.env.JWT_SECRET
        );
        console.log(decoded);
        req.authenticationToken = decoded;
    } catch (error) {
        req.authenticationToken = false;
    }

    res.locals.authenticationToken = req.authenticationToken;
    next();
});

app.get("/", (req, res) => {
    if (req.authenticationToken) {
        return res.render("dashboard-page");
    } else {
        res.render("registration-page");
    }
});

app.get("/login", (req, res) => {
    res.render("login-page");
});

app.get("/register", (req, res) => {
    res.render("registration-page");
});

app.post("/login", async (req, res) => {
    const loginValidationError = [];

    if (typeof req.body.username !== "string") {
        req.body.username = "";
    }
    if (typeof req.body.password !== "string") {
        req.body.password = "";
    }

    logged_username = req.body.username.trim();

    if (!logged_username)
        loginValidationError.push("You must provide a username");

    logged_password = req.body.password;
    if (!logged_password)
        loginValidationError.push("You must provide a password");

    if (logged_username && logged_password) {
        // check if the username is in the database
        const getUsername = db.prepare(
            `SELECT * FROM "user" WHERE username = ?`
        );
        const userExistsCheck = getUsername.get(logged_username);
        if (!userExistsCheck) {
            loginValidationError.push("Invalid username / password");
        } else {
            // check if the password match is in the database
            const passwordMatch = await bcrypt.compare(
                logged_password,
                userExistsCheck.password
            );
            if (!passwordMatch) {
                loginValidationError.push("Invalid username / password");
            } else {
                // cookie handling
                const userToken = jwt.sign(
                    {
                        id: userExistsCheck.id,
                        username: userExistsCheck.username,
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

                res.redirect("/");
            }
        }
    }

    if (loginValidationError.length) {
        return res.render("login-page", { loginValidationError });
    }
});

app.post("/register", async (req, res) => {
    const registrationValidationError = [];

    if (typeof req.body.username !== "string") {
        req.body.username = "";
    }
    if (typeof req.body.password !== "string") {
        req.body.password = "";
    }

    proccessed_username = req.body.username.trim();

    if (!proccessed_username)
        registrationValidationError.push("You must provide a username");

    // check if the username already exists
    const getUsername = db.prepare(`SELECT * FROM "user" WHERE username = ?`);
    const usernameUniqueCheck = getUsername.get(proccessed_username);
    if (usernameUniqueCheck) {
        registrationValidationError.push("Username already exists");
    }

    if (proccessed_username && proccessed_username.length < 3)
        registrationValidationError.push(
            "Username must be at least 3 characters"
        );

    if (proccessed_username && proccessed_username.length > 12)
        registrationValidationError.push(
            "Username cannot exceed 12 characters"
        );

    if (proccessed_username && !proccessed_username.match(/^[a-zA-Z0-9]+$/))
        registrationValidationError.push(
            "Username can only contain letters and numbers"
        );

    // Password validation
    proccessed_password = req.body.password;
    if (!proccessed_password)
        registrationValidationError.push("You must provide a password");

    if (proccessed_password && proccessed_password.length < 8)
        registrationValidationError.push(
            "Password must be at least 8 characters"
        );

    if (proccessed_password && proccessed_password.length > 64)
        registrationValidationError.push(
            "Password cannot exceed 64 characters"
        );

    if (registrationValidationError.length) {
        return res.render("registration-page", { registrationValidationError });
    } else {
        // hash the password
        const salt = await bcrypt.genSalt(10);
        const hash_password = await bcrypt.hash(proccessed_password, salt);

        // query
        db.prepare(`INSERT INTO "user"(username, password) VALUES (? , ?)`).run(
            proccessed_username,
            hash_password
        );

        res.send("Thank you for filling the forms");
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("authentication");
    res.redirect("/");
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
