const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const express = require("express");
const db = require("better-sqlite3")("note-app.db");
var Tokens = require("csrf");
const csrfProtection = require("./middleware/csrfProtection");
require("dotenv").config();

const app = express();
const port = 5030;
const tokens = new Tokens();

app.use(cookieParser());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// global middleware
app.use((req, res, next) => {
    res.locals.registrationValidationError = [];
    res.locals.loginValidationError = [];
    res.locals.postCreationValidationError = [];

    // verify the jwt cookie
    try {
        const decoded = jwt.verify(
            req.cookies.authentication,
            process.env.JWT_SECRET
        );
        req.authenticationToken = decoded;
    } catch (error) {
        req.authenticationToken = false;
    }

    res.locals.authenticationToken = req.authenticationToken;

    let secret = req.cookies._csrfSecret;
    if (!secret) {
        secret = tokens.secretSync();
        res.cookie("_csrfSecret", secret, {
            httpOnly: true,
            secure: false,
            sameSite: "strict",
        });
    }

    const csrfToken = tokens.create(secret);
    res.locals.csrfToken = csrfToken;

    // TO DO: ask if I should create csrf token on every route or globally
    // TO DO: clean all console.log

    next();
});

app.get("/", (req, res) => {
    if (req.authenticationToken) {
        const getAllPosts = db.prepare(
            `SELECT * FROM post WHERE author_id = ?`
        );
        const allPosts = getAllPosts.all(req.authenticationToken.id);

        res.locals.posts = allPosts;

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

app.get("/create-post", (req, res) => {
    res.render("create-post-page");
});

app.get("/post/edit/:post_id", (req, res) => {
    if (req.authenticationToken) {
        const post_id = req.params.post_id;
        const getPost = db.prepare(`SELECT * FROM post WHERE post_id = ?`);
        const post = getPost.get(post_id);
        res.render("edit-post-page", { post });
    } else {
        console.log("This error");
        return res.render("error-page");
    }
});

// TO DO : should I verify the type of post_id ?

app.get("/post/:post_id", (req, res) => {
    // verify if user connected
    if (req.authenticationToken) {
        // verify if the post exists
        const post_id = req.params.post_id;
        const getPost = db.prepare(`SELECT * FROM post WHERE post_id = ?`);
        const post = getPost.get(post_id);
        if (post) {
            res.locals.post = post;
            return res.render("post-page", { post });
        } else {
            console.log("This error");
            return res.render("error-page");
        }
    } else {
        console.log("This error");
        res.render("error-page");
    }
});

// app.get("/post/delete/:post_id", csrfProtection, (req, res) => {
//     res.render("error-page")
// });

app.get("/logout", (req, res) => {
    res.clearCookie("authentication");
    res.redirect("/");
});

app.post("/register", csrfProtection, async (req, res) => {
    const registrationValidationError = [];

    if (typeof req.body.username !== "string") {
        req.body.username = "";
    }
    if (typeof req.body.password !== "string") {
        req.body.password = "";
    }

    const processed_username = req.body.username.trim();

    if (!processed_username)
        registrationValidationError.push("You must provide a username");

    // check if the username already exists
    const getUsername = db.prepare(`SELECT * FROM "user" WHERE username = ?`);
    const usernameUniqueCheck = getUsername.get(processed_username);
    if (usernameUniqueCheck) {
        registrationValidationError.push("Username already taken");
    }

    if (processed_username && processed_username.length < 3)
        registrationValidationError.push(
            "Username must be at least 3 characters"
        );

    if (processed_username && processed_username.length > 12)
        registrationValidationError.push(
            "Username cannot exceed 12 characters"
        );

    if (processed_username && !processed_username.match(/^[a-zA-Z0-9]+$/))
        registrationValidationError.push(
            "Username can only contain letters and numbers"
        );

    // Password validation
    const processed_password = req.body.password;
    if (!processed_password)
        registrationValidationError.push("You must provide a password");

    if (processed_password && processed_password.length < 8)
        registrationValidationError.push(
            "Password must be at least 8 characters"
        );

    if (processed_password && processed_password.length > 64)
        registrationValidationError.push(
            "Password cannot exceed 64 characters"
        );

    if (registrationValidationError.length) {
        return res.render("registration-page", { registrationValidationError });
    } else {
        // hash the password
        const salt = await bcrypt.genSalt(10);
        const hash_password = await bcrypt.hash(processed_password, salt);

        // query
        db.prepare(`INSERT INTO "user"(username, password) VALUES (? , ?)`).run(
            processed_username,
            hash_password
        );

        res.redirect("/login");
    }
});

app.post("/login", csrfProtection, async (req, res) => {
    const loginValidationError = [];

    if (typeof req.body.username !== "string") {
        req.body.username = "";
    }
    if (typeof req.body.password !== "string") {
        req.body.password = "";
    }

    const logged_username = req.body.username.trim();
    const logged_password = req.body.password;

    if (!logged_username)
        loginValidationError.push("You must provide a username");

    if (!logged_password)
        loginValidationError.push("You must provide a password");

    const getUsername = db.prepare(`SELECT * FROM "user" WHERE username = ?`);
    const userExistsCheck = getUsername.get(logged_username);

    if (!userExistsCheck && logged_username.length)
        loginValidationError.push("Invalid username / password");

    // password checking
    if (userExistsCheck && logged_password) {
        const passwordMatch = await bcrypt.compare(
            logged_password,
            userExistsCheck.password
        );

        if (!passwordMatch)
            loginValidationError.push("Invalid username / password");
    }

    if (loginValidationError.length) {
        return res.render("login-page", { loginValidationError });
    }

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
        secure: false,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24,
    });

    res.redirect("/");
});

app.post("/create-post", (req, res) => {
    const postCreationValidationError = [];

    if (typeof req.body.title !== "string") {
        req.body.title = "";
    }
    if (typeof req.body.content !== "string") {
        req.body.content = "";
    }

    const processed_title = req.body.title.trim();
    const processed_content = req.body.content;

    if (!processed_title)
        postCreationValidationError.push("You must provide a title");

    if (!processed_content)
        postCreationValidationError.push("Your post is empty");

    if (postCreationValidationError.length) {
        return res.render("create-post-page", {
            postCreationValidationError,
            title: processed_title,
            content: processed_content,
        });
    }

    const author_id = req.authenticationToken.id;
    const insertPost = db.prepare(
        `INSERT INTO post (post_title, post_content, author_id) VALUES (?, ?, ?)`
    );
    insertPost.run(processed_title, processed_content, author_id);

    res.redirect("/");
});

app.post("/post/edit/:post_id", csrfProtection, (req, res) => {
    const post_id = req.params.post_id;

    if (typeof req.body.post_title !== "string") {
        req.body.post_title = "";
    }
    if (typeof req.body.post_content !== "string") {
        req.body.post_content = "";
    }

    const updtatedPostTitle = req.body.post_title.trim();
    const updtatedPostContent = req.body.post_content;

    const updatePost = db.prepare(
        "UPDATE post SET post_title = ?, post_content = ? WHERE post_id = ?"
    );
    updatePost.run(updtatedPostTitle, updtatedPostContent, post_id);

    res.redirect(`/post/${post_id}`);
});

// TO DO ; should I put csrfToken here ?

app.post("/post/delete/:post_id", (req, res) => {
    if (req.authenticationToken) {
        const post_id = req.params.post_id;
        const deletePost = db.prepare(`DELETE FROM post WHERE post_id = ?`);
        deletePost.run(post_id);
        return res.redirect("/");
    } else {
        console.log("Error");
    }
});

const createTablePost = db.prepare(`
    CREATE TABLE IF NOT EXISTS post(
    post_id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_title STRING NOT NULL,
    post_content STRING NOT NULL,
    post_creation_date TIMESTAMP NOT NULL DEFAULT (datetime('now', 'utc')),
    author_id INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES "user"(id))
    `);
createTablePost.run();

const createTableUser = db.prepare(`
    CREATE TABLE IF NOT EXISTS user(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL)`);
createTableUser.run();

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
