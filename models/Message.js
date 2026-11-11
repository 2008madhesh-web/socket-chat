'use strict';

const mongoose = require('mongoose');

/**
 * A message inside a DM or a group.
 * Reactions are one per person: { user, emoji }.
 */
const messageSchema = new mongoose.Schema(
  {
    conversation: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation',
      required: true
    },

    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },

    text: {
      type: String,
      required: true,
      trim: true,
      maxlength: 500
    },

    // 'result' is the one-line summary left behind by a finished game.
    // 'event' is a note about the chat itself, such as someone being added to a group.
    kind: {
      type: String,
      enum: ['text', 'result', 'event'],
      default: 'text'
    },

    // Disappearing messages: when set, the server deletes the message at this time
    vanishAt: { type: Date },

    // A snapshot of the message being replied to (filled in by the server, never by the client)
    reply: {
      id: String,
      userId: String,
      name: String,
      text: String
    },

    reactions: [
      {
        _id: false,
        user: { type: String, required: true },
        emoji: { type: String, required: true }
      }
    ]
  },
  { timestamps: true }
);

messageSchema.index({ conversation: 1, createdAt: -1 });

module.exports = mongoose.model('Message', messageSchema);
