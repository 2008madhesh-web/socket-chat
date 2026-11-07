const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const MAX_HISTORY = 50;
const MAX_MESSAGE_LENGTH = 500;
const MAX_NAME_LENGTH = 20;
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_WINDOW_MS = 3000;

const history = [];
const users = new Map(); // socket.id -> { name, color }
let nextMessageId = 1;

app.use(express.static(path.join(__dirname, 'public')));

function colorFor(id) {
  let hue = 0;
  for (const ch of id) {
    hue = (hue * 31 + ch.charCodeAt(0)) % 360;
  }
  return `hsl(${hue}, 65%, 45%)`;
}

function cleanName(raw, socketId) {
  const name = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim().slice(0, MAX_NAME_LENGTH) : '';
  return name || 'Anon-' + socketId.slice(0, 4);
}

function broadcastOnline() {
  io.emit('online', {
    count: users.size,
    names: Array.from(users.values()).map((u) => u.name)
  });
}

function systemMessage(text) {
  io.emit('system-message', { text, time: Date.now() });
}

io.on('connection', (socket) => {
  let recentTimes = [];

  socket.on('join', (rawName) => {
    if (users.has(socket.id)) return;

    const user = {
      name: cleanName(rawName, socket.id),
      color: colorFor(socket.id)
    };
    users.set(socket.id, user);

    socket.emit('history', history);
    systemMessage(`${user.name} joined the chat`);
    broadcastOnline();
  });

  socket.on('chat-message', (text) => {
    const user = users.get(socket.id);
    if (!user || typeof text !== 'string') return;

    const message = text.trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!message) return;

    const now = Date.now();
    recentTimes = recentTimes.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (recentTimes.length >= RATE_LIMIT_COUNT) {
      socket.emit('rate-limited');
      return;
    }
    recentTimes.push(now);

    const msg = {
      id: nextMessageId++,
      userId: socket.id.slice(0, 5),
      senderSocketId: socket.id,
      name: user.name,
      color: user.color,
      text: message,
      time: now
    };

    history.push(msg);
    if (history.length > MAX_HISTORY) history.shift();

    io.emit('chat-message', msg);
    socket.broadcast.emit('typing', { id: socket.id, name: user.name, isTyping: false });
  });

  socket.on('typing', (isTyping) => {
    const user = users.get(socket.id);
    if (!user) return;
    socket.broadcast.emit('typing', { id: socket.id, name: user.name, isTyping: Boolean(isTyping) });
  });

  socket.on('disconnect', () => {
    const user = users.get(socket.id);
    if (!user) return;

    users.delete(socket.id);
    io.emit('typing', { id: socket.id, name: user.name, isTyping: false });
    systemMessage(`${user.name} left the chat`);
    broadcastOnline();
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
