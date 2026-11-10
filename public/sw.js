'use strict';

/**
 * Atti chat service worker.
 * It only shows message alerts and opens the right chat when one is tapped.
 * It does not cache anything.
 */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// A message arrived while nobody was looking at the app (the server only sends a push in that case)
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (err) {
    data = {};
  }

  const convo = typeof data.convo === 'string' ? data.convo : '';

  event.waitUntil(
    self.registration.showNotification(data.title || 'Atti chat', {
      body: data.body || 'New message',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      // One alert per chat: a newer message replaces the older one and rings again
      tag: convo ? 'convo:' + convo : 'atti',
      renotify: true,
      silent: false, // play the device's notification sound
      vibrate: [120, 60, 120],
      data: { convo }
    })
  );
});

// Tapping the alert brings the app forward and opens that chat
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const convo = (event.notification.data && event.notification.data.convo) || '';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (list) => {
      for (const client of list) {
        try {
          await client.focus();
          client.postMessage({ type: 'open-chat', convo });
          return;
        } catch (err) {
          /* try the next window */
        }
      }
      return self.clients.openWindow(convo ? '/?chat=' + convo : '/');
    })
  );
});
