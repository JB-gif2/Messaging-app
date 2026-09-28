const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const DB_FILE = path.join(__dirname, "messages.json");
const MAX_HISTORY = 200;

// ---- Simple persistence ----
let messages = [];
try {
  messages = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
} catch {
  messages = [];
}
const save = () =>
  fs.writeFile(DB_FILE, JSON.stringify(messages.slice(-MAX_HISTORY)), () => {});

// ---- State ----
const users = new Map(); // socket.id -> username

const onlineList = () => [...new Set(users.values())];

app.use(express.static(path.join(__dirname, "public")));

io.on("connection", (socket) => {
  socket.on("join", (name, ack) => {
    name = String(name || "").trim().slice(0, 20);
    if (!name) return ack?.({ ok: false, error: "Name required" });
    if (onlineList().includes(name))
      return ack?.({ ok: false, error: "Name already in use" });

    users.set(socket.id, name);
    ack?.({ ok: true, history: messages.slice(-MAX_HISTORY) });
    io.emit("users", onlineList());
    socket.broadcast.emit("system", `${name} joined`);
  });

  socket.on("message", (text) => {
    const user = users.get(socket.id);
    text = String(text || "").trim().slice(0, 1000);
    if (!user || !text) return;

    const msg = { id: Date.now() + Math.random(), user, text, time: Date.now() };
    messages.push(msg);
    if (messages.length > MAX_HISTORY) messages.shift();
    save();
    io.emit("message", msg);
  });

  socket.on("typing", (isTyping) => {
    const user = users.get(socket.id);
    if (user) socket.broadcast.emit("typing", { user, isTyping: !!isTyping });
  });

  socket.on("disconnect", () => {
    const user = users.get(socket.id);
    if (!user) return;
    users.delete(socket.id);
    io.emit("users", onlineList());
    io.emit("system", `${user} left`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Chat running at http://localhost:${PORT}`));