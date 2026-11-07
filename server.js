const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
  // Short anonymous ID derived from the socket ID
  const userId = socket.id.slice(0, 5);

  socket.on('chat-message', (text) => {
    if (typeof text !== 'string') return;

    const message = text.trim().slice(0, 500);
    if (!message) return;

    io.emit('chat-message', {
      id: userId,
      senderSocketId: socket.id,
      text: message,
      time: Date.now()
    });
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
