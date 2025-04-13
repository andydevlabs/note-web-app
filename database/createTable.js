import Database from "better-sqlite3";
const db = new Database("note-app.db");

const createTablePost = () => {
    db.prepare(`
    CREATE TABLE IF NOT EXISTS post(
    post_id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_title STRING NOT NULL,
    post_content STRING NOT NULL,
    post_creation_date TIMESTAMP NOT NULL DEFAULT (datetime('now', 'utc')),
    author_id INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES "user"(id))
    `).run();
};

const createTableUser = () => {
    db.prepare(`
    CREATE TABLE IF NOT EXISTS user(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL)`).run();
};

export { createTablePost, createTableUser };
