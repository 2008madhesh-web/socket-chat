'use strict';

const mongoose = require('mongoose');

/**
 * One browser or phone that has agreed to get message alerts.
 * A person can have several (phone and laptop), so there is one row per device.
 */
const pushSubscriptionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },

    // The address of this device on the browser's push service. Unique, so a device is stored once.
    endpoint: {
      type: String,
      required: true,
      unique: true,
      maxlength: 1000
    },

    keys: {
      p256dh: { type: String, required: true },
      auth: { type: String, required: true }
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('PushSubscription', pushSubscriptionSchema);
