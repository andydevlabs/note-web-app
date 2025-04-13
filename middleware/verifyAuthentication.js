const verifyAuthentication = (req, res, next) => {
    if (!req.authenticationToken) {
        return res.redirect("/login");
    }
    next();
}

export default verifyAuthentication;
