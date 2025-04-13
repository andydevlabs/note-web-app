const paramaterToString = (body, params) => {
    return typeof body[params] === "string" ? body[params] : "";
};

export { paramaterToString };
