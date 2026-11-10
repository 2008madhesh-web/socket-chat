'use strict';

/**
 * Atti chat - server
 * Express + Socket.io + MongoDB Atlas (Mongoose)
 * Auth: Passport Local (username/password + bcrypt) and Google OAuth 2.0
 *
 * Required environment variables:
 *   MONGO_URI              MongoDB Atlas connection string
 *   SESSION_SECRET         long random string used to sign session cookies
 * Optional (enables "Sign in with Google"):
 *   GOOGLE_CLIENT_ID
 *   GOOGLE_CLIENT_SECRET
 * Optional:
 *   BASE_URL               public URL of the site (defaults to Render's URL, then localhost)
 */

const path = require('path');
const http = require('http');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const User = require('./models/User');
const Conversation = require('./models/Conversation');
const Message = require('./models/Message');

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.RENDER);
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const SESSION_SECRET = process.env.SESSION_SECRET || (isProd ? null : 'dev-only-secret-change-me');
const BASE_URL = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const GOOGLE_ENABLED = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (!MONGO_URI) {
  console.error('Missing MONGO_URI environment variable.');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error('Missing SESSION_SECRET environment variable.');
  process.exit(1);
}

const SESSION_COOKIE_NAME = 'atti.sid';
const SESSION_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_BYTES = 72; // bcrypt only uses the first 72 bytes

const MAX_HISTORY = 50;
const MAX_MESSAGE_LENGTH = 500;
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_WINDOW_MS = 3000;

/* ------------------------------------------------------------------ */
/* App, HTTP server and Socket.io                                      */
/* ------------------------------------------------------------------ */

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render sits behind a proxy; needed for secure cookies and rate limiting

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '10kb' }));

/* ------------------------------------------------------------------ */
/* Sessions (stored in MongoDB so logins survive restarts)             */
/* ------------------------------------------------------------------ */

const sessionMiddleware = session({
  name: SESSION_COOKIE_NAME,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    collectionName: 'sessions',
    ttl: SESSION_MAX_AGE_MS / 1000
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax', // 'lax' is required so the cookie survives the redirect back from Google
    secure: isProd,
    maxAge: SESSION_MAX_AGE_MS
  }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

// Stable avatar colour derived from the user id
function colorFor(id) {
  let hue = 0;
  for (const ch of String(id)) {
    hue = (hue * 31 + ch.charCodeAt(0)) % 360;
  }
  return `hsl(${hue}, 65%, 45%)`;
}

// The only user fields the browser is allowed to see
function serializeUser(user) {
  return {
    id: user.id,
    username: user.username || null,
    displayName: user.displayName,
    avatar: user.avatar || '',
    color: colorFor(user.id)
  };
}

function cleanDisplayName(raw, fallback) {
  const name = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim().slice(0, 30) : '';
  return name || fallback;
}

// Used to keep login timing the same whether or not the username exists
const DUMMY_HASH = bcrypt.hashSync('atti-chat-dummy-password', 12);

/* ------------------------------------------------------------------ */
/* Passport: Local strategy (username + password)                      */
/* ------------------------------------------------------------------ */

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      if (typeof username !== 'string' || typeof password !== 'string') {
        return done(null, false, { message: 'Enter your username and password.' });
      }

      const user = await User.findOne({ username: username.trim().toLowerCase() }).select('+password');

      // Always run a bcrypt comparison so response time does not reveal valid usernames
      const hash = user && user.password ? user.password : DUMMY_HASH;
      const matches = await bcrypt.compare(password, hash);

      if (!user || !user.password || !matches) {
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

/* ------------------------------------------------------------------ */
/* Passport: Google OAuth 2.0 strategy                                 */
/* ------------------------------------------------------------------ */

if (GOOGLE_ENABLED) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/auth/google/callback`,
        proxy: true
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : '';

          let user = await User.findOne({ googleId: profile.id });

          if (!user) {
            // First time with Google: create the account
            user = await User.create({
              googleId: profile.id,
              displayName: cleanDisplayName(profile.displayName, 'Google user'),
              avatar
            });
          } else if (avatar && user.avatar !== avatar) {
            // Keep the profile picture fresh
            user.avatar = avatar;
            await user.save();
          }

          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
} else {
  console.warn('Google login is disabled: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable it.');
}

// Store only the user id inside the session...
passport.serializeUser((user, done) => done(null, user.id));

// ...and load the full user from MongoDB on each request
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || false);
  } catch (err) {
    done(err);
  }
});

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

// Slow down password guessing and account spamming
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' }
});

// Health check (handy for Render)
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// Create a local account and log in straight away
app.post('/api/signup', authLimiter, async (req, res, next) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'Username must be 3-20 characters: letters, numbers or underscores.' });
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
    }
    if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
      return res.status(400).json({ error: 'Password is too long. Use 72 bytes or fewer.' });
    }

    if (await User.exists({ username })) {
      return res.status(409).json({ error: 'That username is already taken.' });
    }

    const user = await User.create({
      username,
      password: await User.hashPassword(password),
      displayName: cleanDisplayName(req.body.displayName, username)
    });

    req.login(user, (err) => {
      if (err) return next(err);
      res.status(201).json({ user: serializeUser(user) });
    });
  } catch (err) {
    // Two people grabbed the same username at the same moment
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'That username is already taken.' });
    }
    next(err);
  }
});

// Log in with username + password
app.post('/api/login', authLimiter, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).json({ error: (info && info.message) || 'Incorrect username or password.' });
    }
    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      res.json({ user: serializeUser(user) });
    });
  })(req, res, next);
});

// Log out and close any open chat connections for this user
app.post('/api/logout', (req, res, next) => {
  const userId = req.user ? req.user.id : null;

  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie(SESSION_COOKIE_NAME);
      if (userId) io.in(`user:${userId}`).disconnectSockets(true);
      res.json({ ok: true });
    });
  });
});

// Tell the browser whether it is logged in
app.get('/api/check-auth', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (req.isAuthenticated()) {
    return res.json({ authenticated: true, user: serializeUser(req.user) });
  }
  res.json({ authenticated: false });
});

// Choose a profile picture from the built-in set
const AVATAR_PRESETS = ['fox', 'cat', 'panda', 'robot', 'alien', 'owl', 'ghost', 'frog', 'astronaut', 'penguin'];
const avatarLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many changes. Please wait a minute and try again.' }
});

app.post('/api/avatar', avatarLimiter, async (req, res, next) => {
  try {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Please log in first.' });

    const choice = typeof req.body.avatar === 'string' ? req.body.avatar : '';
    if (!AVATAR_PRESETS.includes(choice)) {
      return res.status(400).json({ error: 'Pick one of the available avatars.' });
    }

    const avatar = `preset:${choice}`;
    req.user.avatar = avatar;
    await req.user.save();

    // Update old messages, the user's open tabs, and everyone currently in the room
    history.forEach((m) => { if (m.userId === req.user.id) m.avatar = avatar; });
    const sockets = await io.in(`user:${req.user.id}`).fetchSockets();
    sockets.forEach((s) => { s.data.avatar = avatar; });
    io.emit('avatar-updated', { userId: req.user.id, avatar });
    const online = presence.get(req.user.id);
    if (online) {
      online.avatar = avatar;
      broadcastOnline();
    }

    res.json({ user: serializeUser(req.user) });
  } catch (err) {
    next(err);
  }
});

// Start Google sign-in
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_ENABLED) return res.redirect('/?error=google_unavailable');
  passport.authenticate('google', { scope: ['profile'] })(req, res, next);
});

// Google sends the user back here
app.get(
  '/auth/google/callback',
  (req, res, next) => {
    if (!GOOGLE_ENABLED) return res.redirect('/?error=google_unavailable');
    passport.authenticate('google', { failureRedirect: '/?error=google_failed' })(req, res, next);
  },
  (req, res) => res.redirect('/')
);

// Find people to start a chat with (used by the "New chat" sheet)
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many searches. Please wait a moment.' }
});

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

app.get('/api/users/search', searchLimiter, async (req, res, next) => {
  try {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Please log in first.' });

    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 30) : '';
    const filter = { _id: { $ne: req.user._id } };
    if (q) {
      const re = new RegExp(escapeRegex(q), 'i');
      filter.$or = [{ displayName: re }, { username: re }];
    }

    const users = await User.find(filter)
      .select('displayName username avatar')
      .sort(q ? { displayName: 1 } : { createdAt: -1 })
      .limit(12);

    res.json({ users: users.map(serializeUser) });
  } catch (err) {
    next(err);
  }
});

// Catch-all error handler (keeps stack traces away from users)
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: status === 400 ? 'Invalid request.' : 'Something went wrong. Please try again.' });
});

/* ------------------------------------------------------------------ */
/* Socket.io: share the Express session so only logged-in users connect */
/* ------------------------------------------------------------------ */

// Run the middleware only for the first (handshake) request of a connection
function onlyForHandshake(middleware) {
  return (req, res, next) => {
    const isHandshake = req._query.sid === undefined;
    if (isHandshake) {
      middleware(req, res, next);
    } else {
      next();
    }
  };
}

io.engine.use(onlyForHandshake(sessionMiddleware));
io.engine.use(onlyForHandshake(passport.initialize()));
io.engine.use(onlyForHandshake(passport.session()));
io.engine.use(
  onlyForHandshake((req, res, next) => {
    if (req.user) {
      next();
    } else {
      res.writeHead(401);
      res.end();
    }
  })
);

/* ------------------------------------------------------------------ */
/* Chat                                                                */
/* ------------------------------------------------------------------ */

const history = []; // last MAX_HISTORY messages (in memory)
const presence = new Map(); // userId -> { name, avatar, color, connections }
let nextMessageId = 1;

/* ------------------------------------------------------------------ */
/* Reactions + small shared helpers                                    */
/* ------------------------------------------------------------------ */

// The reactions people can pick. The browser shows the same six.
const REACTIONS = ['\u2764\uFE0F', '\uD83D\uDE02', '\uD83D\uDC4D', '\uD83D\uDE2E', '\uD83D\uDE22', '\uD83D\uDD25'];
const MAX_GROUP_NAME = 40;
const MAX_GROUP_MEMBERS = 50;
const OBJECT_ID_RE = /^[a-f\d]{24}$/i;

const isId = (value) => typeof value === 'string' && OBJECT_ID_RE.test(value);

// [{ user, emoji }] -> { emoji: [userId, ...] }
function publicReactions(list) {
  const out = {};
  for (const r of list || []) {
    (out[r.emoji] = out[r.emoji] || []).push(String(r.user));
  }
  return out;
}

// One reaction per person: the same emoji again removes it, a different one replaces it
function toggleReaction(list, userId, emoji) {
  const plain = (list || []).map((r) => ({ user: String(r.user), emoji: r.emoji }));
  const had = plain.find((r) => r.user === userId);
  const next = plain.filter((r) => r.user !== userId);
  if (!had || had.emoji !== emoji) next.push({ user: userId, emoji });
  return next;
}

// Allows `count` actions per `windowMs`; one limiter per connection
function makeLimiter(count, windowMs) {
  let times = [];
  return () => {
    const now = Date.now();
    times = times.filter((t) => now - t < windowMs);
    if (times.length >= count) return false;
    times.push(now);
    return true;
  };
}

function publicMessage(m) {
  return { ...m, reactions: publicReactions(m.reactions) };
}

function broadcastOnline() {
  io.emit('online', {
    count: presence.size,
    users: Array.from(presence, ([id, p]) => ({ id, name: p.name, avatar: p.avatar, color: p.color }))
  });
}

function systemMessage(text) {
  io.emit('system-message', { text, time: Date.now() });
}

/* ------------------------------------------------------------------ */
/* Disappearing messages + 1v1 games (Tic-Tac-Toe, Connect Four)       */
/* ------------------------------------------------------------------ */

const VANISH_MS = 10 * 1000; // how long a disappearing message lives
const FORFEIT_GRACE_MS = 15 * 1000; // a refresh should not forfeit a game
const END_DELAY_MS = 3500; // how long the finished board stays up before it turns into a result line
const MAX_STROKES = 400; // drawing game limits keep memory small
const MAX_POINTS = 15000;
const GAME_LABELS = { ttt: 'Tic-Tac-Toe', c4: 'Connect Four', draw: 'Drawing' };
const disappearUsers = new Set(); // userIds who have disappear mode switched on
const games = new Map(); // gameId -> game
let nextGameId = 1;

const TTT_LINES = [
  [0, 1, 2], [3, 4, 5], [6, 7, 8],
  [0, 3, 6], [1, 4, 7], [2, 5, 8],
  [0, 4, 8], [2, 4, 6]
];
const C4_ROWS = 6;
const C4_COLS = 7;

// Adds the seconds left, so each browser can run its own countdown without trusting its clock
function withTtl(m) {
  const out = m.reactions ? publicMessage(m) : m;
  return out.vanishAt ? { ...out, ttl: Math.max(0, out.vanishAt - Date.now()) } : out;
}

// The public room's history and running games, sent on connect and when switching back to the room
function sendMain(socket) {
  socket.emit('games', Array.from(games.values()).map(publicGame));
  socket.emit('history', history.map(withTtl));
}

function scheduleVanish(msg) {
  setTimeout(() => {
    const i = history.findIndex((m) => m.id === msg.id);
    if (i !== -1) history.splice(i, 1);
    io.emit('message-vanish', { id: msg.id });
  }, VANISH_MS).unref();
}

function tttWinner(board) {
  for (const line of TTT_LINES) {
    const [a, b, c] = line;
    if (board[a] && board[a] === board[b] && board[a] === board[c]) return line;
  }
  return null;
}

function c4Winner(board) {
  const dirs = [[0, 1], [1, 0], [1, 1], [1, -1]];
  for (let r = 0; r < C4_ROWS; r++) {
    for (let c = 0; c < C4_COLS; c++) {
      const v = board[r * C4_COLS + c];
      if (!v) continue;
      for (const [dr, dc] of dirs) {
        const line = [r * C4_COLS + c];
        for (let k = 1; k < 4; k++) {
          const rr = r + dr * k;
          const cc = c + dc * k;
          if (rr < 0 || rr >= C4_ROWS || cc < 0 || cc >= C4_COLS) break;
          if (board[rr * C4_COLS + cc] !== v) break;
          line.push(rr * C4_COLS + cc);
        }
        if (line.length === 4) return line;
      }
    }
  }
  return null;
}

// The only game fields the browser needs
function publicGame(g) {
  return {
    id: g.id,
    type: g.type,
    status: g.status, // open | playing | won | draw | cancelled
    challenger: g.challenger,
    opponent: g.opponent,
    board: g.board,
    turn: g.turn,
    winner: g.winner,
    line: g.line,
    lastMove: g.lastMove,
    reason: g.reason,
    strokes: g.type === 'draw' ? g.strokes : undefined
  };
}

function broadcastGame(g) {
  io.emit('game-update', publicGame(g));
}

// The one-line summary that replaces a finished game card in the chat
function resultText(g) {
  const a = g.challenger.name;
  const b = g.opponent ? g.opponent.name : '';
  const label = GAME_LABELS[g.type];
  if (g.type === 'draw') return `${a} and ${b} finished a drawing together`;
  if (g.status === 'draw') return `${a} and ${b} drew at ${label}`;
  const winner = g.winner === g.challenger.id ? g.challenger : g.opponent;
  const loser = winner === g.challenger ? g.opponent : g.challenger;
  if (g.reason === 'resigned') return `${loser.name} resigned. ${winner.name} won ${label}`;
  if (g.reason === 'left') return `${loser.name} left. ${winner.name} won ${label}`;
  return `${winner.name} won ${label} against ${loser.name}`;
}

// Game over: show the final board briefly, then swap the card for a result line.
// A cancelled challenge just disappears.
function endGame(g) {
  if (g.status === 'cancelled') return removeGame(g, null);
  broadcastGame(g);
  const text = resultText(g);
  setTimeout(() => removeGame(g, text), END_DELAY_MS).unref();
}

function removeGame(g, text) {
  if (!games.has(g.id)) return;
  games.delete(g.id);
  const i = history.findIndex((m) => m.type === 'game' && m.gameId === g.id);
  let result = null;
  if (text) {
    result = { type: 'result', text, time: Date.now() };
    if (i !== -1) history[i] = result;
  } else if (i !== -1) {
    history.splice(i, 1);
  }
  io.emit('game-remove', { id: g.id, result });
}

// One open or running game per person keeps things simple and fair
function userBusy(userId) {
  for (const g of games.values()) {
    if (g.status !== 'open' && g.status !== 'playing') continue;
    if (g.challenger.id === userId || (g.opponent && g.opponent.id === userId)) return true;
  }
  return false;
}

// Forget games whose card has scrolled out of the chat history
function pruneGames() {
  const live = new Set(history.filter((m) => m.type === 'game').map((m) => m.gameId));
  for (const id of games.keys()) {
    if (!live.has(id)) games.delete(id);
  }
}

function registerExtraHandlers(socket, userId, name) {
  const fail = (message) => socket.emit('game-error', { message });
  let lastCreate = 0;

  // ----- disappear mode -----
  socket.on('set-disappear', (on) => {
    if (on === true) disappearUsers.add(userId);
    else disappearUsers.delete(userId);
    io.in(`user:${userId}`).emit('disappear-state', on === true);
  });

  // ----- challenges -----
  socket.on('create-game', (type) => {
    if (type !== 'ttt' && type !== 'c4' && type !== 'draw') return;

    const now = Date.now();
    if (now - lastCreate < 2000) return fail('Slow down a little.');
    if (userBusy(userId)) return fail('Finish or cancel your current game first.');
    lastCreate = now;

    const game = {
      id: nextGameId++,
      type,
      status: 'open',
      challenger: { id: userId, name },
      opponent: null,
      board: type === 'draw' ? [] : new Array(type === 'ttt' ? 9 : C4_ROWS * C4_COLS).fill(null),
      strokes: [],
      strokeMap: new Map(),
      totalPts: 0,
      turn: null,
      winner: null,
      line: null,
      lastMove: null,
      reason: null
    };
    games.set(game.id, game);

    history.push({ type: 'game', gameId: game.id, time: now });
    if (history.length > MAX_HISTORY) history.shift();
    pruneGames();

    io.emit('game-new', { game: publicGame(game), time: now });
  });

  socket.on('accept-game', (gameId) => {
    const g = games.get(gameId);
    if (!g || g.status !== 'open') return fail('That challenge is no longer open.');
    if (g.challenger.id === userId) return fail("You can't accept your own challenge.");
    if (userBusy(userId)) return fail('Finish or cancel your current game first.');

    g.opponent = { id: userId, name };
    g.status = 'playing';
    g.turn = g.challenger.id; // the challenger goes first
    broadcastGame(g);
  });

  socket.on('cancel-game', (gameId) => {
    const g = games.get(gameId);
    if (!g || g.status !== 'open' || g.challenger.id !== userId) return;
    g.status = 'cancelled';
    endGame(g);
  });

  socket.on('resign-game', (gameId) => {
    const g = games.get(gameId);
    if (!g || g.status !== 'playing' || g.type === 'draw') return;
    const isChallenger = g.challenger.id === userId;
    if (!isChallenger && g.opponent.id !== userId) return;

    g.status = 'won';
    g.winner = isChallenger ? g.opponent.id : g.challenger.id;
    g.reason = 'resigned';
    endGame(g);
  });

  // ----- moves: the server decides whose turn it is and whether the move is legal -----
  socket.on('make-move', (data) => {
    if (!data || typeof data !== 'object') return;
    const g = games.get(data.gameId);
    if (!g || g.status !== 'playing' || g.type === 'draw' || g.turn !== userId) return;

    const index = data.index;
    if (!Number.isInteger(index)) return;

    const isChallenger = g.challenger.id === userId;

    if (g.type === 'ttt') {
      if (index < 0 || index > 8 || g.board[index]) return;
      g.board[index] = isChallenger ? 'X' : 'O';
      g.lastMove = index;
      g.line = tttWinner(g.board);
    } else {
      // Connect Four: index is the column, the disc falls to the lowest free row
      if (index < 0 || index >= C4_COLS) return;
      let row = -1;
      for (let r = C4_ROWS - 1; r >= 0; r--) {
        if (!g.board[r * C4_COLS + index]) { row = r; break; }
      }
      if (row === -1) return; // column is full
      const cell = row * C4_COLS + index;
      g.board[cell] = isChallenger ? 'R' : 'Y';
      g.lastMove = cell;
      g.line = c4Winner(g.board);
    }

    if (g.line) {
      g.status = 'won';
      g.winner = userId;
    } else if (g.board.every(Boolean)) {
      g.status = 'draw';
    } else {
      g.turn = isChallenger ? g.opponent.id : g.challenger.id;
    }
    if (g.status === 'playing') broadcastGame(g);
    else endGame(g);
  });

  // ----- drawing together -----
  let drawWindow = 0;
  let drawCount = 0;
  const isPlayerOf = (g) => g.challenger.id === userId || (g.opponent && g.opponent.id === userId);

  socket.on('draw-seg', (d) => {
    if (!d || typeof d !== 'object') return;
    const g = games.get(d.gameId);
    if (!g || g.type !== 'draw' || g.status !== 'playing' || !isPlayerOf(g)) return;

    // flood guard: a fast hand sends well under 60 batches a second
    const now = Date.now();
    if (now - drawWindow > 1000) { drawWindow = now; drawCount = 0; }
    if (++drawCount > 120) return;

    if (!Number.isInteger(d.sid) || !Number.isInteger(d.c) || d.c < 0 || d.c > 5) return;
    if (!Number.isInteger(d.w) || d.w < 0 || d.w > 2) return;
    if (!Array.isArray(d.pts) || d.pts.length === 0 || d.pts.length > 60) return;

    const pts = [];
    for (const p of d.pts) {
      if (!Array.isArray(p) || p.length !== 2) return;
      const x = Math.round(p[0]);
      const y = Math.round(p[1]);
      if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || x > 1000 || y < 0 || y > 1000) return;
      pts.push([x, y]);
    }

    const key = `${userId}:${d.sid}`;
    let stroke = g.strokeMap.get(key);
    if (!stroke) {
      if (g.strokes.length >= MAX_STROKES || g.totalPts >= MAX_POINTS) {
        return fail('The canvas is full. Clear it to keep drawing.');
      }
      stroke = { u: userId, s: d.sid, c: d.c, w: d.w, pts: [] };
      g.strokes.push(stroke);
      g.strokeMap.set(key, stroke);
    }
    if (g.totalPts + pts.length > MAX_POINTS) return;
    for (const p of pts) stroke.pts.push(p);
    g.totalPts += pts.length;

    socket.broadcast.emit('draw-seg', { gameId: g.id, u: userId, s: d.sid, c: stroke.c, w: stroke.w, pts });
  });

  socket.on('draw-clear', (gameId) => {
    const g = games.get(gameId);
    if (!g || g.type !== 'draw' || g.status !== 'playing' || !isPlayerOf(g)) return;
    g.strokes = [];
    g.strokeMap.clear();
    g.totalPts = 0;
    io.emit('draw-clear', { gameId: g.id });
  });

  socket.on('finish-game', (gameId) => {
    const g = games.get(gameId);
    if (!g || g.type !== 'draw' || g.status !== 'playing' || !isPlayerOf(g)) return;
    g.status = 'done';
    endGame(g);
  });

  // If someone really leaves (not just a refresh), end their games
  socket.on('disconnect', () => {
    setTimeout(() => {
      if (presence.has(userId)) return;
      for (const g of games.values()) {
        if (g.status === 'open' && g.challenger.id === userId) {
          g.status = 'cancelled';
          endGame(g);
        } else if (g.status === 'playing' && (g.challenger.id === userId || g.opponent.id === userId)) {
          if (g.type === 'draw') {
            g.status = 'done';
          } else {
            g.status = 'won';
            g.winner = g.challenger.id === userId ? g.opponent.id : g.challenger.id;
            g.reason = 'left';
          }
          endGame(g);
        }
      }
    }, FORFEIT_GRACE_MS).unref();
  });
}

/* ------------------------------------------------------------------ */
/* Direct messages, groups and reactions                               */
/* ------------------------------------------------------------------ */

function emitToMembers(memberIds, event, payload) {
  if (!memberIds.length) return;
  io.to(memberIds.map((id) => `user:${id}`)).emit(event, payload);
}

// What the browser sees of a conversation (members must be populated)
function serializeConvo(c) {
  const last = c.lastMessage && c.lastMessage.time ? c.lastMessage : null;
  return {
    id: c.id,
    type: c.type,
    name: c.name || '',
    color: colorFor(c.id),
    members: (c.members || []).map(serializeUser),
    lastMessage: last
      ? { text: last.text || '', userId: String(last.sender), time: last.time.getTime() }
      : null,
    createdAt: c.createdAt.getTime()
  };
}

async function listConversations(userId) {
  const docs = await Conversation.find({ members: userId })
    .populate('members', 'displayName username avatar')
    .sort({ updatedAt: -1 })
    .limit(200);
  return docs.map(serializeConvo);
}

// sender: { id, displayName, avatar }
function publicConvoMessage(m, sender) {
  const msg = {
    id: String(m._id),
    convo: String(m.conversation),
    userId: sender ? sender.id : String(m.sender),
    name: sender ? sender.displayName : 'Deleted user',
    avatar: sender ? sender.avatar || '' : '',
    color: colorFor(sender ? sender.id : String(m.sender)),
    text: m.text,
    time: m.createdAt.getTime(),
    ttl: 0,
    reactions: publicReactions(m.reactions)
  };
  if (m.reply && m.reply.id) {
    msg.reply = { id: m.reply.id, userId: m.reply.userId, name: m.reply.name, text: m.reply.text };
  }
  return msg;
}

function registerConversationHandlers(socket, user, allowSend) {
  const userId = user.id;
  const fail = (message) => socket.emit('convo-error', { message });
  const allowReact = makeLimiter(12, 3000);
  const allowCreate = makeLimiter(5, 10000);
  const memberCache = new Map(); // conversationId -> [memberId, ...] (only conversations this user belongs to)

  // Returns the member ids if this user belongs to the conversation, otherwise null
  async function memberIdsOf(convoId) {
    if (memberCache.has(convoId)) return memberCache.get(convoId);
    const c = await Conversation.findOne({ _id: convoId, members: userId }).select('members').lean();
    if (!c) return null;
    const ids = c.members.map(String);
    memberCache.set(convoId, ids);
    return ids;
  }

  // Tell every member about a new conversation, then open it for whoever started it
  async function announce(convo, toIds) {
    await convo.populate('members', 'displayName username avatar');
    memberCache.set(convo.id, convo.members.map((m) => m.id));
    emitToMembers(toIds, 'convo:new', serializeConvo(convo));
    socket.emit('convo:started', { id: convo.id });
  }

  socket.on('convo:list', async () => {
    try {
      socket.emit('convo:list', await listConversations(userId));
    } catch (err) {
      console.error(err);
    }
  });

  // Switch to a conversation: 'main' is the public room, anything else is a DM or group
  socket.on('convo:open', async (id) => {
    try {
      if (id === 'main') return sendMain(socket);
      if (!isId(id)) return;

      if (!(await memberIdsOf(id))) return fail('You are not part of that chat.');

      const docs = await Message.find({ conversation: id })
        .sort({ createdAt: -1 })
        .limit(MAX_HISTORY)
        .populate('sender', 'displayName avatar')
        .lean();

      const messages = docs.reverse().map((m) =>
        publicConvoMessage(
          m,
          m.sender && m.sender._id
            ? { id: String(m.sender._id), displayName: m.sender.displayName, avatar: m.sender.avatar }
            : null
        )
      );
      socket.emit('convo:history', { id, messages });
    } catch (err) {
      console.error(err);
      fail('Could not open that chat.');
    }
  });

  socket.on('dm:start', async (otherId) => {
    try {
      if (!isId(otherId) || otherId === userId) return;
      if (!allowCreate()) return fail('Slow down a little.');
      if (!(await User.exists({ _id: otherId }))) return fail('That person could not be found.');

      const dmKey = Conversation.dmKeyFor(userId, otherId);
      let convo = await Conversation.findOne({ dmKey });
      let created = false;

      if (!convo) {
        try {
          convo = await Conversation.create({ type: 'dm', members: [userId, otherId], createdBy: userId, dmKey });
          created = true;
        } catch (err) {
          if (!err || err.code !== 11000) throw err;
          convo = await Conversation.findOne({ dmKey }); // both people started it at the same moment
        }
      }

      // A brand new DM is announced to both people; an existing one only needs to open for this user
      await announce(convo, created ? [userId, otherId] : [userId]);
    } catch (err) {
      console.error(err);
      fail('Could not start that chat.');
    }
  });

  socket.on('group:create', async (data) => {
    try {
      if (!data || typeof data !== 'object') return;
      if (!allowCreate()) return fail('Slow down a little.');

      const name = typeof data.name === 'string' ? data.name.replace(/\s+/g, ' ').trim().slice(0, MAX_GROUP_NAME) : '';
      if (!name) return fail('Give your group a name.');

      const others = Array.isArray(data.members)
        ? Array.from(new Set(data.members.filter(isId))).filter((id) => id !== userId)
        : [];
      if (others.length < 1) return fail('Pick at least one person.');
      if (others.length + 1 > MAX_GROUP_MEMBERS) return fail(`A group can have up to ${MAX_GROUP_MEMBERS} people.`);

      if ((await User.countDocuments({ _id: { $in: others } })) !== others.length) {
        return fail('Some of those people could not be found.');
      }

      const members = [userId, ...others];
      const convo = await Conversation.create({ type: 'group', name, members, createdBy: userId });
      await announce(convo, members);
    } catch (err) {
      console.error(err);
      fail('Could not create that group.');
    }
  });

  socket.on('convo:message', async (payload) => {
    try {
      if (!payload || typeof payload !== 'object' || !isId(payload.id)) return;

      const text = typeof payload.text === 'string' ? payload.text.trim().slice(0, MAX_MESSAGE_LENGTH) : '';
      if (!text) return;

      if (!allowSend()) {
        socket.emit('rate-limited');
        return;
      }

      const members = await memberIdsOf(payload.id);
      if (!members) return fail('You are not part of that chat.');

      // Reply: the server looks up the original itself, so a client cannot fake what someone said
      let reply;
      if (isId(payload.replyTo)) {
        const orig = await Message.findOne({ _id: payload.replyTo, conversation: payload.id })
          .populate('sender', 'displayName')
          .lean();
        if (orig) {
          reply = {
            id: String(orig._id),
            userId: String(orig.sender && orig.sender._id ? orig.sender._id : orig.sender),
            name: orig.sender && orig.sender.displayName ? orig.sender.displayName : 'Deleted user',
            text: orig.text.slice(0, 100)
          };
        }
      }

      const doc = await Message.create({ conversation: payload.id, sender: userId, text, reply });
      await Conversation.updateOne(
        { _id: payload.id },
        { $set: { lastMessage: { text: text.slice(0, 100), sender: userId, time: doc.createdAt } } }
      );

      const avatar = socket.data.avatar !== undefined ? socket.data.avatar : user.avatar;
      const msg = publicConvoMessage(doc, { id: userId, displayName: user.displayName, avatar });
      emitToMembers(members, 'convo:message', msg);
      io.to(members.map((id) => `user:${id}`))
        .except(`user:${userId}`)
        .emit('convo:typing', { convo: payload.id, id: userId, name: user.displayName, isTyping: false });
    } catch (err) {
      console.error(err);
      fail('Could not send that message.');
    }
  });

  socket.on('convo:typing', (data) => {
    if (!data || typeof data !== 'object' || !isId(data.id)) return;
    const members = memberCache.get(data.id); // only conversations opened on this connection
    if (!members) return;
    io.to(members.map((id) => `user:${id}`))
      .except(`user:${userId}`)
      .emit('convo:typing', { convo: data.id, id: userId, name: user.displayName, isTyping: Boolean(data.isTyping) });
  });

  // Add, change or remove your reaction on a message (public room or a DM / group)
  socket.on('react', async (data) => {
    try {
      if (!data || typeof data !== 'object' || !REACTIONS.includes(data.emoji)) return;
      if (!allowReact()) return;

      if (data.convo === 'main') {
        const m = history.find((x) => x.id !== undefined && x.id === data.id);
        if (!m) return;
        m.reactions = toggleReaction(m.reactions, userId, data.emoji);
        io.emit('reaction-update', { convo: 'main', id: m.id, reactions: publicReactions(m.reactions) });
        return;
      }

      if (!isId(data.convo) || !isId(data.id)) return;
      const members = await memberIdsOf(data.convo);
      if (!members) return;

      const doc = await Message.findOne({ _id: data.id, conversation: data.convo });
      if (!doc) return;
      doc.reactions = toggleReaction(doc.reactions, userId, data.emoji);
      await doc.save();
      emitToMembers(members, 'reaction-update', {
        convo: data.convo,
        id: data.id,
        reactions: publicReactions(doc.reactions)
      });
    } catch (err) {
      console.error(err);
    }
  });
}

io.on('connection', (socket) => {
  const user = socket.request.user; // set by Passport during the handshake
  const userId = user.id;
  const name = user.displayName;
  const avatar = user.avatar || '';
  const color = colorFor(userId);

  // Every tab of the same user joins one private room (used for logout and typing)
  socket.join(`user:${userId}`);

  sendMain(socket);
  registerExtraHandlers(socket, userId, name);

  // One limiter for the public room and for DMs / groups
  const allowSend = makeLimiter(RATE_LIMIT_COUNT, RATE_LIMIT_WINDOW_MS);
  registerConversationHandlers(socket, user, allowSend);
  listConversations(userId)
    .then((list) => socket.emit('convo:list', list))
    .catch((err) => console.error(err));

  // Count tabs so a user with two tabs open is shown only once
  const existing = presence.get(userId);
  if (existing) {
    existing.connections += 1;
  } else {
    presence.set(userId, { name, avatar, color, connections: 1 });
    systemMessage(`${name} joined the chat`);
  }
  broadcastOnline();

  socket.on('chat-message', (payload) => {
    const isObject = payload !== null && typeof payload === 'object';
    const text = typeof payload === 'string' ? payload : isObject ? payload.text : null;
    if (typeof text !== 'string') return;

    const message = text.trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!message) return;

    // Simple per-connection rate limit (shared with DMs and groups)
    if (!allowSend()) {
      socket.emit('rate-limited');
      return;
    }
    const now = Date.now();

    // Reply: the server looks up the original itself, so a client cannot fake what someone said.
    // Disappearing originals are quoted without their text.
    let reply = null;
    if (isObject && Number.isInteger(payload.replyTo)) {
      const orig = history.find((m) => m.id === payload.replyTo);
      if (orig && typeof orig.text === 'string') {
        reply = {
          id: orig.id,
          userId: orig.userId,
          name: orig.name,
          text: orig.vanishAt ? '' : orig.text.slice(0, 100)
        };
      }
    }

    const msg = {
      id: nextMessageId++,
      userId,
      name,
      avatar: socket.data.avatar !== undefined ? socket.data.avatar : avatar,
      color,
      text: message,
      time: now,
      vanishAt: disappearUsers.has(userId) ? now + VANISH_MS : null,
      ttl: disappearUsers.has(userId) ? VANISH_MS : 0,
      reactions: []
    };
    if (reply) msg.reply = reply;

    history.push(msg);
    if (history.length > MAX_HISTORY) history.shift();

    io.emit('chat-message', publicMessage(msg));
    if (msg.vanishAt) scheduleVanish(msg);
    socket.broadcast.except(`user:${userId}`).emit('typing', { id: userId, name, isTyping: false });
  });

  socket.on('typing', (isTyping) => {
    socket.broadcast.except(`user:${userId}`).emit('typing', { id: userId, name, isTyping: Boolean(isTyping) });
  });

  socket.on('disconnect', () => {
    const entry = presence.get(userId);
    if (!entry) return;

    entry.connections -= 1;
    if (entry.connections <= 0) {
      presence.delete(userId);
      io.emit('typing', { id: userId, name, isTyping: false });
      systemMessage(`${name} left the chat`);
    }
    broadcastOnline();
  });
});

/* ------------------------------------------------------------------ */
/* Start up and shut down                                              */
/* ------------------------------------------------------------------ */

async function start() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('Could not connect to MongoDB:', err.message);
    process.exit(1);
  }

  server.listen(PORT, () => {
    console.log(`Atti chat running on port ${PORT}`);
  });
}

function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);
  io.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start();
