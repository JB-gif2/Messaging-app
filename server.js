const express = require("express");
const session = require("express-session");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const webpush = require("web-push");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const USERS_FILE = path.join(__dirname, "users.json");
const MESSAGES_FILE = path.join(__dirname, "messages.json");
const GROUPS_FILE = path.join(__dirname, "groups.json");
const SUBS_FILE = path.join(__dirname, "subscriptions.json");
const VAPID_FILE = path.join(__dirname, "vapid.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");
const MAX_PER_CHAT = 200;
const MAX_TOTAL_MESSAGES = 5000;

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---- Simple JSON "database" helpers ----
// NOTE: On free hosting tiers the disk is often wiped on restart/redeploy,
// so these files and uploaded photos may reset. Fine for an MVP demo;
// swap in a real database (e.g. Postgres) when that matters.
function loadJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function saveJSON(file, data) {
  fs.writeFile(file, JSON.stringify(data), () => {});
}

let users = loadJSON(USERS_FILE, []); // { id, username, passwordHash, name, photo, createdAt }
let messages = loadJSON(MESSAGES_FILE, []); // { id, chatId, type:'direct'|'group', from, to?, text, time, status?, tempId? }
let groups = loadJSON(GROUPS_FILE, []); // { id, name, members:[{userId,role}], lastRead:{userId:ts}, createdBy, createdAt }
let subscriptions = loadJSON(SUBS_FILE, []); // { id, userId, subscription }

const findUserByUsername = (u) =>
  users.find((x) => x.username.toLowerCase() === String(u).toLowerCase());
const findUserById = (id) => users.find((x) => x.id === id);
const chatIdOf = (a, b) => [a, b].sort().join("_");

const findGroupById = (id) => groups.find((g) => g.id === id);
const isMember = (group, userId) => group.members.some((m) => m.userId === userId);
const memberRole = (group, userId) => group.members.find((m) => m.userId === userId)?.role;
const isAdmin = (group, userId) => memberRole(group, userId) === "admin";

function groupPublic(group) {
  return {
    id: group.id,
    name: group.name,
    photo: null,
    members: group.members
      .map((m) => {
        const u = findUserById(m.userId);
        return u ? { ...publicUser(u), role: m.role } : null;
      })
      .filter(Boolean),
  };
}

// ---- Web Push setup ----
// Generate VAPID keys once and reuse them across restarts (they identify
// this server to push services; changing them breaks existing subscriptions).
let vapidKeys = loadJSON(VAPID_FILE, null);
let pushEnabled = true;
if (!vapidKeys) {
  try {
    vapidKeys = webpush.generateVAPIDKeys();
    fs.writeFileSync(VAPID_FILE, JSON.stringify(vapidKeys));
  } catch (err) {
    // Some sandboxed environments (e.g. StackBlitz's WebContainer) don't support
    // the elliptic-curve crypto VAPID needs. Don't let that take the whole server
    // down — just disable push notifications and keep everything else working.
    console.warn("Push notifications disabled in this environment: " + err.message);
    pushEnabled = false;
  }
}
if (pushEnabled) {
  webpush.setVapidDetails("mailto:admin@example.com", vapidKeys.publicKey, vapidKeys.privateKey);
}

async function notifyOffline(recipient, senderName, text) {
  if (!pushEnabled) return;
  const subs = subscriptions.filter((s) => s.userId === recipient.id);
  if (!subs.length) return;
  const payload = JSON.stringify({ title: senderName, body: text.slice(0, 120), url: "/" });
  for (const s of subs) {
    try {
      await webpush.sendNotification(s.subscription, payload);
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        subscriptions = subscriptions.filter((x) => x.id !== s.id);
        saveJSON(SUBS_FILE, subscriptions);
      }
    }
  }
}

// ---- Session, shared between Express routes and Socket.IO ----
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "dev-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }, // 7 days
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---- Photo upload config ----
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS_DIR,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname) || ".jpg";
      cb(null, crypto.randomUUID() + ext);
    },
  }),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith("image/")),
});

function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, photo: u.photo || null };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ ok: false, error: "Not logged in" });
  next();
}

// ---- Auth routes ----
app.post("/api/signup", upload.single("photo"), (req, res) => {
  const cleanUser = String(req.body.username || "").trim().toLowerCase().slice(0, 20);
  const cleanName = String(req.body.name || "").trim().slice(0, 40) || cleanUser;
  const password = String(req.body.password || "");

  if (!cleanUser || !password) {
    return res.status(400).json({ ok: false, error: "Username and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, error: "Password must be at least 6 characters" });
  }
  if (findUserByUsername(cleanUser)) {
    return res.status(400).json({ ok: false, error: "Username already taken" });
  }

  const user = {
    id: crypto.randomUUID(),
    username: cleanUser,
    passwordHash: bcrypt.hashSync(password, 10),
    name: cleanName,
    photo: req.file ? "/uploads/" + req.file.filename : null,
    createdAt: Date.now(),
  };
  users.push(user);
  saveJSON(USERS_FILE, users);

  req.session.userId = user.id;
  res.json({ ok: true, user: publicUser(user) });
});

app.post("/api/login", (req, res) => {
  const user = findUserByUsername(String(req.body.username || ""));
  if (!user || !bcrypt.compareSync(String(req.body.password || ""), user.passwordHash)) {
    return res.status(400).json({ ok: false, error: "Invalid username or password" });
  }
  req.session.userId = user.id;
  res.json({ ok: true, user: publicUser(user) });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  const user = req.session.userId && findUserById(req.session.userId);
  if (!user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: publicUser(user) });
});

app.post("/api/profile", requireAuth, upload.single("photo"), (req, res) => {
  const user = findUserById(req.session.userId);
  if (req.body.name) user.name = String(req.body.name).trim().slice(0, 40);
  if (req.file) user.photo = "/uploads/" + req.file.filename;
  saveJSON(USERS_FILE, users);
  res.json({ ok: true, user: publicUser(user) });
});

// ---- Push subscription routes ----
app.get("/api/push/publicKey", (req, res) => {
  if (!pushEnabled) return res.json({ ok: false, error: "Push notifications aren't available in this environment" });
  res.json({ ok: true, key: vapidKeys.publicKey });
});

app.post("/api/push/subscribe", requireAuth, (req, res) => {
  if (!pushEnabled) return res.status(400).json({ ok: false, error: "Push notifications aren't available in this environment" });
  const sub = req.body.subscription;
  if (!sub || !sub.endpoint) return res.status(400).json({ ok: false, error: "Invalid subscription" });
  subscriptions = subscriptions.filter((s) => s.subscription.endpoint !== sub.endpoint);
  subscriptions.push({ id: crypto.randomUUID(), userId: req.session.userId, subscription: sub });
  saveJSON(SUBS_FILE, subscriptions);
  res.json({ ok: true });
});

app.post("/api/push/unsubscribe", requireAuth, (req, res) => {
  subscriptions = subscriptions.filter((s) => s.subscription.endpoint !== req.body.endpoint);
  saveJSON(SUBS_FILE, subscriptions);
  res.json({ ok: true });
});

// ---- Contacts route ----
app.get("/api/users", requireAuth, (req, res) => {
  res.json({
    ok: true,
    users: users.filter((u) => u.id !== req.session.userId).map(publicUser),
  });
});

// ---- Unified chat list: direct chats + group chats ----
app.get("/api/chats", requireAuth, (req, res) => {
  const me = req.session.userId;
  const results = [];

  // Direct chats
  const byPartner = new Map();
  for (const m of messages) {
    if (m.type === "group") continue;
    if (m.from !== me && m.to !== me) continue;
    const partnerId = m.from === me ? m.to : m.from;
    const entry = byPartner.get(partnerId) || { lastMessage: null, unread: 0 };
    if (!entry.lastMessage || m.time > entry.lastMessage.time) entry.lastMessage = m;
    if (m.to === me && m.status !== "read") entry.unread++;
    byPartner.set(partnerId, entry);
  }
  for (const [partnerId, entry] of byPartner) {
    const partner = findUserById(partnerId);
    if (!partner) continue;
    results.push({
      type: "direct",
      id: partner.id,
      title: partner.name,
      photo: partner.photo,
      online: onlineUsers.has(partner.id),
      lastMessage: {
        text: entry.lastMessage.text,
        time: entry.lastMessage.time,
        fromMe: entry.lastMessage.from === me,
        fromName: null,
      },
      unread: entry.unread,
    });
  }

  // Group chats
  for (const g of groups.filter((g) => isMember(g, me))) {
    const groupMsgs = messages.filter((m) => m.chatId === g.id);
    const last = groupMsgs[groupMsgs.length - 1];
    const readMarker = (g.lastRead && g.lastRead[me]) || 0;
    const unread = groupMsgs.filter((m) => m.from !== me && m.time > readMarker).length;
    results.push({
      type: "group",
      id: g.id,
      title: g.name,
      photo: null,
      online: false,
      lastMessage: last
        ? {
            text: last.text,
            time: last.time,
            fromMe: last.from === me,
            fromName: last.from === me ? null : findUserById(last.from)?.name || "Someone",
          }
        : { text: "No messages yet", time: g.createdAt, fromMe: false, fromName: null },
      unread,
    });
  }

  results.sort((a, b) => b.lastMessage.time - a.lastMessage.time);
  res.json({ ok: true, chats: results });
});

app.get("/api/messages/:userId", requireAuth, (req, res) => {
  const other = findUserById(req.params.userId);
  if (!other) return res.status(404).json({ ok: false, error: "User not found" });
  const chatId = chatIdOf(req.session.userId, other.id);
  const history = messages.filter((m) => m.chatId === chatId).slice(-MAX_PER_CHAT);
  res.json({ ok: true, messages: history, user: publicUser(other) });
});

// ---- Group routes ----
function broadcastGroupUpdate(group) {
  const pub = groupPublic(group);
  for (const m of group.members) {
    for (const sid of onlineUsers.get(m.userId) || []) io.to(sid).emit("group_updated", pub);
  }
}

app.post("/api/groups", requireAuth, (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 50);
  const memberIds = Array.isArray(req.body.memberIds)
    ? req.body.memberIds.filter((id) => findUserById(id) && id !== req.session.userId)
    : [];
  if (!name) return res.status(400).json({ ok: false, error: "Group name is required" });
  if (!memberIds.length) return res.status(400).json({ ok: false, error: "Pick at least one member" });

  const group = {
    id: "grp_" + crypto.randomUUID(),
    name,
    members: [
      { userId: req.session.userId, role: "admin" },
      ...memberIds.map((id) => ({ userId: id, role: "member" })),
    ],
    lastRead: { [req.session.userId]: Date.now() },
    createdBy: req.session.userId,
    createdAt: Date.now(),
  };
  groups.push(group);
  saveJSON(GROUPS_FILE, groups);
  broadcastGroupUpdate(group);
  res.json({ ok: true, group: groupPublic(group) });
});

app.get("/api/groups/:id", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  res.json({ ok: true, group: groupPublic(group) });
});

app.get("/api/groups/:id/messages", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  const history = messages.filter((m) => m.chatId === group.id).slice(-MAX_PER_CHAT);
  res.json({ ok: true, messages: history, group: groupPublic(group) });
});

app.post("/api/groups/:id/members", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  if (!isAdmin(group, req.session.userId)) return res.status(403).json({ ok: false, error: "Only admins can add members" });
  const ids = Array.isArray(req.body.memberIds) ? req.body.memberIds : [];
  let added = false;
  for (const id of ids) {
    if (findUserById(id) && !isMember(group, id)) {
      group.members.push({ userId: id, role: "member" });
      added = true;
    }
  }
  if (!added) return res.status(400).json({ ok: false, error: "No new members to add" });
  saveJSON(GROUPS_FILE, groups);
  broadcastGroupUpdate(group);
  res.json({ ok: true, group: groupPublic(group) });
});

app.post("/api/groups/:id/remove", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  if (!isAdmin(group, req.session.userId)) return res.status(403).json({ ok: false, error: "Only admins can remove members" });
  const targetId = req.body.userId;
  if (targetId === req.session.userId) return res.status(400).json({ ok: false, error: "Use leave instead" });
  if (!isMember(group, targetId)) return res.status(400).json({ ok: false, error: "Not a member" });

  const notifySockets = [...(onlineUsers.get(targetId) || [])];
  group.members = group.members.filter((m) => m.userId !== targetId);
  saveJSON(GROUPS_FILE, groups);
  for (const sid of notifySockets) io.to(sid).emit("group_removed", { groupId: group.id });
  broadcastGroupUpdate(group);
  res.json({ ok: true, group: groupPublic(group) });
});

app.post("/api/groups/:id/leave", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  group.members = group.members.filter((m) => m.userId !== req.session.userId);

  if (group.members.length === 0) {
    groups = groups.filter((g) => g.id !== group.id);
    saveJSON(GROUPS_FILE, groups);
    return res.json({ ok: true, deleted: true });
  }
  if (!group.members.some((m) => m.role === "admin")) {
    group.members[0].role = "admin"; // keep the group from ending up with no admin
  }
  saveJSON(GROUPS_FILE, groups);
  broadcastGroupUpdate(group);
  res.json({ ok: true });
});

app.post("/api/groups/:id/role", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  if (!isAdmin(group, req.session.userId)) return res.status(403).json({ ok: false, error: "Only admins can change roles" });
  const { userId, role } = req.body;
  if (!["admin", "member"].includes(role)) return res.status(400).json({ ok: false, error: "Invalid role" });
  const member = group.members.find((m) => m.userId === userId);
  if (!member) return res.status(400).json({ ok: false, error: "Not a member" });

  const adminCount = group.members.filter((m) => m.role === "admin").length;
  if (member.role === "admin" && role === "member" && adminCount <= 1) {
    return res.status(400).json({ ok: false, error: "A group needs at least one admin" });
  }
  member.role = role;
  saveJSON(GROUPS_FILE, groups);
  broadcastGroupUpdate(group);
  res.json({ ok: true, group: groupPublic(group) });
});

app.patch("/api/groups/:id", requireAuth, (req, res) => {
  const group = findGroupById(req.params.id);
  if (!group || !isMember(group, req.session.userId)) return res.status(404).json({ ok: false, error: "Group not found" });
  if (!isAdmin(group, req.session.userId)) return res.status(403).json({ ok: false, error: "Only admins can rename the group" });
  const name = String(req.body.name || "").trim().slice(0, 50);
  if (!name) return res.status(400).json({ ok: false, error: "Name is required" });
  group.name = name;
  saveJSON(GROUPS_FILE, groups);
  broadcastGroupUpdate(group);
  res.json({ ok: true, group: groupPublic(group) });
});

// ---- Socket.IO (private 1:1 + group messaging) ----
const onlineUsers = new Map(); // userId -> Set of socket ids

io.on("connection", (socket) => {
  const userId = socket.request.session?.userId;
  const user = userId && findUserById(userId);
  if (!user) {
    socket.emit("auth_error", "Please log in");
    return socket.disconnect(true);
  }

  if (!onlineUsers.has(user.id)) onlineUsers.set(user.id, new Set());
  onlineUsers.get(user.id).add(socket.id);
  io.emit("presence", [...onlineUsers.keys()]);

  // Mark any direct messages waiting for this user as delivered, and notify senders.
  const deliveredBySender = new Map();
  for (const m of messages) {
    if (m.type !== "group" && m.to === user.id && m.status === "sent") {
      m.status = "delivered";
      if (!deliveredBySender.has(m.from)) deliveredBySender.set(m.from, []);
      deliveredBySender.get(m.from).push(m.id);
    }
  }
  if (deliveredBySender.size) {
    saveJSON(MESSAGES_FILE, messages);
    for (const [senderId, ids] of deliveredBySender) {
      const chatId = chatIdOf(senderId, user.id);
      for (const sid of onlineUsers.get(senderId) || []) {
        io.to(sid).emit("delivered", { chatId, ids });
      }
    }
  }

  socket.on("private_message", ({ to, text, tempId }) => {
    const recipient = findUserById(to);
    text = String(text || "").trim().slice(0, 1000);
    if (!recipient || !text) return;

    const chatId = chatIdOf(user.id, recipient.id);
    const recipientOnline = onlineUsers.has(recipient.id);
    const msg = {
      id: crypto.randomUUID(),
      chatId,
      type: "direct",
      from: user.id,
      to: recipient.id,
      text,
      time: Date.now(),
      status: recipientOnline ? "delivered" : "sent",
      ...(tempId ? { tempId } : {}),
    };
    messages.push(msg);
    if (messages.length > MAX_TOTAL_MESSAGES) messages.shift();
    saveJSON(MESSAGES_FILE, messages);

    for (const sid of onlineUsers.get(recipient.id) || []) io.to(sid).emit("private_message", msg);
    for (const sid of onlineUsers.get(user.id) || []) io.to(sid).emit("private_message", msg);

    if (!recipientOnline) notifyOffline(recipient, user.name, text);
  });

  socket.on("read", ({ otherUserId }) => {
    const chatId = chatIdOf(user.id, otherUserId);
    const changedIds = [];
    for (const m of messages) {
      if (m.chatId === chatId && m.to === user.id && m.status !== "read") {
        m.status = "read";
        changedIds.push(m.id);
      }
    }
    if (changedIds.length) {
      saveJSON(MESSAGES_FILE, messages);
      for (const sid of onlineUsers.get(otherUserId) || []) {
        io.to(sid).emit("read_receipt", { chatId, ids: changedIds });
      }
    }
  });

  socket.on("group_message", ({ groupId, text, tempId }) => {
    const group = findGroupById(groupId);
    text = String(text || "").trim().slice(0, 1000);
    if (!group || !isMember(group, user.id) || !text) return;

    const msg = {
      id: crypto.randomUUID(),
      chatId: group.id,
      type: "group",
      from: user.id,
      text,
      time: Date.now(),
      ...(tempId ? { tempId } : {}),
    };
    messages.push(msg);
    if (messages.length > MAX_TOTAL_MESSAGES) messages.shift();
    saveJSON(MESSAGES_FILE, messages);

    group.lastRead = group.lastRead || {};
    group.lastRead[user.id] = msg.time;
    saveJSON(GROUPS_FILE, groups);

    for (const m of group.members) {
      for (const sid of onlineUsers.get(m.userId) || []) io.to(sid).emit("group_message", msg);
      if (m.userId !== user.id && !onlineUsers.has(m.userId)) {
        const recipient = findUserById(m.userId);
        if (recipient) notifyOffline(recipient, `${user.name} (${group.name})`, text);
      }
    }
  });

  socket.on("group_read", ({ groupId }) => {
    const group = findGroupById(groupId);
    if (!group || !isMember(group, user.id)) return;
    group.lastRead = group.lastRead || {};
    group.lastRead[user.id] = Date.now();
    saveJSON(GROUPS_FILE, groups);
  });

  socket.on("typing", ({ to, isTyping }) => {
    for (const sid of onlineUsers.get(to) || []) {
      io.to(sid).emit("typing", { from: user.id, isTyping: !!isTyping });
    }
  });

  socket.on("disconnect", () => {
    const set = onlineUsers.get(user.id);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) onlineUsers.delete(user.id);
    }
    io.emit("presence", [...onlineUsers.keys()]);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Chat running at http://localhost:${PORT}`));