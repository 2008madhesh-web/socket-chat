'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Higher = slower to brute-force, but slower to log in. 12 is a solid default.
const BCRYPT_ROUNDS = 12;

/**
 * A user can exist in two ways:
 *  - Local account:  username + hashed password
 *  - Google account: googleId (no username or password)
 *
 * `unique` + `sparse` lets many documents omit a field while still keeping
 * the values that do exist unique (Google users have no username, local
 * users have no googleId).
 */
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 20,
      match: [/^[a-z0-9_]+$/, 'Username can only contain letters, numbers and underscores.']
    },

    // Stores the bcrypt hash only, never the plain password.
    // `select: false` keeps it out of normal queries; ask for it explicitly with .select('+password').
    password: {
      type: String,
      select: false
    },

    googleId: {
      type: String,
      unique: true,
      sparse: true
    },

    displayName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 30
    },

    // Profile picture URL (filled from Google; empty for local accounts)
    avatar: {
      type: String,
      default: '',
      trim: true,
      maxlength: 500
    }
  },
  { timestamps: true }
);

// A brand new user must have either (username + password) or a googleId.
userSchema.pre('validate', function (next) {
  if (!this.isNew) return next();

  const hasLocalLogin = Boolean(this.username && this.password);
  const hasGoogleLogin = Boolean(this.googleId);

  if (!hasLocalLogin && !hasGoogleLogin) {
    return next(new Error('A user needs either a username and password, or a Google account.'));
  }
  next();
});

// Turn a plain password into a bcrypt hash.
userSchema.statics.hashPassword = function (plainPassword) {
  return bcrypt.hash(plainPassword, BCRYPT_ROUNDS);
};

// Compare a plain password with this user's stored hash.
// The document must have been loaded with .select('+password').
userSchema.methods.verifyPassword = function (plainPassword) {
  if (!this.password) return Promise.resolve(false);
  return bcrypt.compare(plainPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
