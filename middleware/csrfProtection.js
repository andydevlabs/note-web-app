const Tokens = require("csrf");
const tokens = new Tokens();

function csrfProtection(req, res, next) {
    const csrfSecret = req.cookies._csrfSecret;

    if (!csrfSecret) {
        return res.status(403).send("Missing CSRF secret");
    }

    const csrfToken = req.body._csrf;

    if (!tokens.verify(csrfSecret, csrfToken)) {
        return res.status(403).send("Invalid CSRF token");
    }

    next();
}

module.exports = csrfProtection;
