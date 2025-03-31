const express = require("express");
const app = express();
const port = 3000;

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    res.locals.validationError = [];
    next();
});

app.get("/", (req, res) => {
    res.render("homePage");
});

app.get("/login", (req, res) => {
    res.render("loginPage");
});

app.post("/register", (req, res) => {
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

    if (validationError.length) {
        return res.render("homePage", { validationError });
    } else {
        res.send("Thank you for feeling the forms");
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
