import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import express from "express";
import Database from "better-sqlite3";
import Tokens from "csrf";
import csrfProtection from "./middleware/csrfProtection.js";
import dotenv from "dotenv";
import verifyAuthentication from "./middleware/verifyAuthentication.js";
import {paramaterToString } from "./helpers/paramaterToString.js";
import { createTablePost, createTableUser } from "./database/createTable.js";

dotenv.config();
const app = express();
const port = 5030;
const tokens = new Tokens();
const db = new Database("note-app.db");

createTablePost();
createTableUser();

app.set("view engine", "ejs");
app.use(cookieParser());
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

    next();
});

app.get("/", verifyAuthentication, (req, res) => {
    const getAllPosts = db.prepare(`SELECT * FROM post WHERE author_id = ?`);
    const allPosts = getAllPosts.all(req.authenticationToken.id);

    res.locals.posts = allPosts;

    return res.render("dashboard-page");
});

app.get("/login", (req, res) => {
    res.render("login-page");
});

app.get("/register", (req, res) => {
    res.render("registration-page");
});

app.get("/create-post", verifyAuthentication, (req, res) => {
    res.render("create-post-page");
});

const postRouteParamsVerification = (req, res, toVerify) => {
    const params = parseInt(toVerify);
    if (isNaN(params) || params <= 0) {
        return { error: true, message: "Invalid post ID" };
    }
    const getPost = db.prepare(
        `SELECT * FROM post WHERE post_id = ? AND author_id = ?`
    );
    const post = getPost.get(params, req.authenticationToken.id);

    if (!post) {
        return { error: true, message: "Post not found" };
    }

    return { error: false, post: post };
};

app.get("/post/edit/:post_id", verifyAuthentication, (req, res) => {
    const result = postRouteParamsVerification(req, res, req.params.post_id);
    if (result.error) {
        return res.render("error-page");
    }
    return res.render("edit-post-page", { post: result.post });
});

app.get("/post/:post_id", verifyAuthentication, (req, res) => {
    const result = postRouteParamsVerification(req, res, req.params.post_id);
    if (result.error) {
        return res.render("error-page");
    }
    return res.render("post-page", { post: result.post });
});

app.get("/logout", (req, res) => {
    res.clearCookie("authentication");
    res.redirect("/");
});

app.post(
    "/post/delete/:post_id",
    csrfProtection,
    verifyAuthentication,
    (req, res) => {
        const result = postRouteParamsVerification(
            req,
            res,
            req.params.post_id
        );
        if (result.error) {
            return res.render("error-page");
        }

        const deletePost = db.prepare(
            `DELETE FROM post WHERE post_id = ? AND author_id = ?`
        );
        deletePost.run(req.params.post_id, req.authenticationToken.id);

        return res.redirect("/");
    }
);

app.post(
    "/post/edit/:post_id",
    csrfProtection,
    verifyAuthentication,
    (req, res) => {
        const post_id = req.params.post_id;
        const result = postRouteParamsVerification(req, res, post_id);

        if (result.error) {
            return res.render("error-page");
        }

        const updatedTitle = req.body.post_title.trim();
        const updatedcontent = req.body.post_content;
        const updatePost = db.prepare(
            "UPDATE post SET post_title = ?, post_content = ? WHERE post_id = ? AND author_id = ?"
        );
        updatePost.run(
            updatedTitle,
            updatedcontent,
            post_id,
            req.authenticationToken.id
        );

        return res.redirect(`/post/${post_id}`);
    }
);

app.post("/register", csrfProtection, async (req, res) => {
    const registrationValidationError = [];
    paramaterToString(req.body, "username");
    paramaterToString(req.body, "password");

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
    paramaterToString(req.body, "username");
    paramaterToString(req.body, "password");

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

app.post("/create-post", csrfProtection, verifyAuthentication, (req, res) => {
    const postCreationValidationError = [];
    paramaterToString(req.body, "post_title");
    paramaterToString(req.body, "post_content");

    const processed_title = req.body.post_title.trim();
    const processed_content = req.body.post_content;

    if (!processed_title)
        postCreationValidationError.push("You must provide a title");

    if (!processed_content)
        postCreationValidationError.push("Your post is empty");

    if (postCreationValidationError.length) {
        return res.render("create-post-page", {
            postCreationValidationError,
            post_title: processed_title,
            post_content: processed_content,
        });
    }

    const author_id = req.authenticationToken.id;
    const insertPost = db.prepare(
        `INSERT INTO post (post_title, post_content, author_id) VALUES (?, ?, ?)`
    );
    insertPost.run(processed_title, processed_content, author_id);

    res.redirect("/");
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
