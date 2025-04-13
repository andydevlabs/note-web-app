import Tokens from "csrf";
const tokens = new Tokens();

const csrfProtection = (req, res, next) => {
    const csrfSecret = req.cookies._csrfSecret;

    if (!csrfSecret) {
        return res.status(403).send("Missing CSRF secret");
    }

    const csrfToken = req.body._csrf;

    if (!tokens.verify(csrfSecret, csrfToken)) {
        return res.render("error-page");
    }

    next();
}

export default csrfProtection;
