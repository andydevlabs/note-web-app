const express = require("express");
const app = express();
const port = 3000;

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true}))

app.get("/", (req, res) => {
    res.render("homePage");
});

app.get("/login", (req, res) => {
    res.render("loginPage");
});

app.post("/register", (req, res) => {
    res.send("Form filled")
    console.log(req.body);
})

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
