'use strict';

const mongoose = require('mongoose');

/**
 * A private conversation: either a direct message (exactly two members)
 * or a group (a name and two or more members).
 *
 * The public "Everyone" room is not stored here; it lives in memory in server.js.
 */
const conversationSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ['dm', 'group'],
      required: true
    },

    // Groups only
    name: {
      type: String,
      trim: true,
      maxlength: 40
    },

    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],

    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

    // DMs only: the two user ids sorted and joined, so a pair of people can only ever have one DM
    dmKey: {
      type: String,
      unique: true,
      sparse: true
    },

    // When each member last read this chat. A message counts as seen by a person
    // if it was sent at or before their `at`. New group members start at the moment they joined.
    reads: [
      {
        _id: false,
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        at: { type: Date, required: true }
      }
    ],

    // Denormalised so the chat list can show a preview without loading messages
    lastMessage: {
      text: { type: String, maxlength: 100 },
      sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      time: { type: Date }
    }
  },
  { timestamps: true }
);

conversationSchema.index({ members: 1, updatedAt: -1 });

conversationSchema.pre('validate', function (next) {
  if (this.type === 'dm') {
    if (this.members.length !== 2 || !this.dmKey) {
      return next(new Error('A direct message needs exactly two members.'));
    }
  } else if (this.type === 'group') {
    if (!this.name) return next(new Error('A group needs a name.'));
    if (this.members.length < 2) return next(new Error('A group needs at least two members.'));
  }
  next();
});

// Stable key for a pair of users
conversationSchema.statics.dmKeyFor = function (idA, idB) {
  return [String(idA), String(idB)].sort().join(':');
};

module.exports = mongoose.model('Conversation', conversationSchema);
