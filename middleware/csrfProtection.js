const Tokens = require("csrf");
const tokens = new Tokens();

function csrfProtection(req, res, next) {
    const csrfSecret = req.cookies._csrfSecret;

    if (!csrfSecret) {
        return res.status(403).send("Missing CSRF secret");
    }

    const csrfToken = req.body._csrf;

    if (!tokens.verify(csrfSecret, csrfToken)) {
                console.log("This error");
        return res.render("error-page");
    }

    next();
}

module.exports = csrfProtection;
