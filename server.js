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
const presence = new Map(); // userId -> { name, connections }
let nextMessageId = 1;

function broadcastOnline() {
  io.emit('online', {
    count: presence.size,
    names: Array.from(presence.values()).map((p) => p.name)
  });
}

function systemMessage(text) {
  io.emit('system-message', { text, time: Date.now() });
}

io.on('connection', (socket) => {
  const user = socket.request.user; // set by Passport during the handshake
  const userId = user.id;
  const name = user.displayName;
  const avatar = user.avatar || '';
  const color = colorFor(userId);

  // Every tab of the same user joins one private room (used for logout and typing)
  socket.join(`user:${userId}`);

  socket.emit('history', history);

  // Count tabs so a user with two tabs open is shown only once
  const existing = presence.get(userId);
  if (existing) {
    existing.connections += 1;
  } else {
    presence.set(userId, { name, connections: 1 });
    systemMessage(`${name} joined the chat`);
  }
  broadcastOnline();

  let recentTimes = [];

  socket.on('chat-message', (text) => {
    if (typeof text !== 'string') return;

    const message = text.trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!message) return;

    // Simple per-connection rate limit
    const now = Date.now();
    recentTimes = recentTimes.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (recentTimes.length >= RATE_LIMIT_COUNT) {
      socket.emit('rate-limited');
      return;
    }
    recentTimes.push(now);

    const msg = {
      id: nextMessageId++,
      userId,
      name,
      avatar: socket.data.avatar !== undefined ? socket.data.avatar : avatar,
      color,
      text: message,
      time: now
    };

    history.push(msg);
    if (history.length > MAX_HISTORY) history.shift();

    io.emit('chat-message', msg);
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
