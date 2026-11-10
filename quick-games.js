'use strict';

const crypto = require('node:crypto');

/**
 * Rules for the three quick games: Memory Match, Rock Paper Scissors and Reaction Duel.
 *
 * Like Tic-Tac-Toe and Connect Four, these are decided on the server. The browser only
 * sends what the player did (flip a card, pick a hand, tap) and the server works out what
 * happened. Anything a player must not see yet (the hidden cards, the other player's pick,
 * when the duel signal will fire) never leaves this file until it is allowed to.
 *
 * server.js passes in how to broadcast a game and how to end one. Timers, the clock and the
 * random source can be swapped too, which is how the tests run a whole game instantly.
 */

const TYPES = new Set(['mem', 'rps', 'duel']);

const MEM_PAIRS = 8; // a 4x4 board
const MEM_HIDE_MS = 1200; // how long a wrong pair stays face up

const RPS_TARGET = 2; // first to two rounds wins (best of three)
const RPS_REVEAL_MS = 2600; // shake, flip, read the result, then the next round

const DUEL_TARGET = 3; // first to three rounds wins (best of five)
const DUEL_READY_MS = 1400; // "Get ready"
const DUEL_WAIT_MIN_MS = 1800; // the red screen lasts a random time in this range
const DUEL_WAIT_MAX_MS = 5200;
const DUEL_GO_TIMEOUT_MS = 5000; // nobody tapped: the round is replayed
const DUEL_REVEAL_MS = 2400;

function createQuickGames(deps) {
  const broadcast = deps.broadcast;
  const finish = deps.finish;
  const schedule =
    deps.schedule ||
    ((fn, ms) => {
      const t = setTimeout(fn, ms);
      if (t.unref) t.unref();
      return t;
    });
  const cancel = deps.cancel || clearTimeout;
  const now = deps.now || Date.now;
  const randomInt = deps.randomInt || crypto.randomInt;

  const isQuick = (type) => TYPES.has(type);
  const alive = (g) => g.status === 'playing';

  // 0 = the challenger, 1 = the opponent, -1 = someone just watching
  function sideOf(g, userId) {
    if (g.challenger.id === userId) return 0;
    if (g.opponent && g.opponent.id === userId) return 1;
    return -1;
  }
  const idOf = (g, side) => (side === 0 ? g.challenger.id : g.opponent.id);

  function setTimer(g, ms, fn) {
    if (g.timer) cancel(g.timer);
    g.timer = schedule(() => {
      g.timer = null;
      if (alive(g)) fn();
    }, ms);
  }

  function winBy(g, side) {
    g.status = 'won';
    g.winner = idOf(g, side);
    finish(g);
  }

  /* ---------------------------------------------------------------- */
  /* Memory Match                                                      */
  /* ---------------------------------------------------------------- */

  function shuffled(list) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = randomInt(0, i + 1);
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  function memMove(g, userId, index) {
    if (g.turn !== userId || g.lock) return;
    if (!Number.isInteger(index) || index < 0 || index >= MEM_PAIRS * 2) return;
    if (g.board[index] !== null) return; // already face up or already claimed

    const side = sideOf(g, userId);
    if (g.flipped.length === 0) g.hit = null;

    g.board[index] = g.deck[index];
    g.flipped.push(index);
    g.lastMove = index;

    if (g.flipped.length < 2) {
      broadcast(g);
      return;
    }

    const [a, b] = g.flipped;

    // A pair: it is theirs, and they go again
    if (g.deck[a] === g.deck[b]) {
      g.owners[a] = side;
      g.owners[b] = side;
      g.scores[side] += 1;
      g.flipped = [];
      g.hit = true;

      if (g.scores[0] + g.scores[1] === MEM_PAIRS) {
        if (g.scores[0] === g.scores[1]) {
          g.status = 'draw';
          finish(g);
        } else {
          winBy(g, g.scores[0] > g.scores[1] ? 0 : 1);
        }
      } else {
        broadcast(g);
      }
      return;
    }

    // Not a pair: leave both face up for a moment so everyone can see them, then pass the turn
    g.hit = false;
    g.lock = true;
    broadcast(g);
    setTimer(g, MEM_HIDE_MS, () => {
      g.board[a] = null;
      g.board[b] = null;
      g.flipped = [];
      g.lock = false;
      g.turn = idOf(g, 1 - side);
      broadcast(g);
    });
  }

  /* ---------------------------------------------------------------- */
  /* Rock Paper Scissors: 0 = rock, 1 = paper, 2 = scissors            */
  /* ---------------------------------------------------------------- */

  function rpsMove(g, userId, choice) {
    if (g.phase !== 'pick') return;
    if (!Number.isInteger(choice) || choice < 0 || choice > 2) return;
    const side = sideOf(g, userId);
    if (side < 0 || g.picks[side] !== null) return; // no changing your mind

    g.picks[side] = choice;
    g.picked[side] = true;

    // Wait for the other player. Nothing about the pick is sent out yet.
    if (g.picks[0] === null || g.picks[1] === null) {
      broadcast(g);
      return;
    }

    const [a, b] = g.picks;
    // Each hand beats the one before it: paper beats rock, scissors beat paper, rock beats scissors
    let winner = null;
    if (a !== b) winner = (a - b + 3) % 3 === 1 ? 0 : 1;

    g.last = { picks: [a, b], winner };
    g.phase = 'reveal';
    if (winner !== null) g.scores[winner] += 1;

    if (winner !== null && g.scores[winner] >= g.target) {
      winBy(g, winner);
      return;
    }

    broadcast(g);
    setTimer(g, RPS_REVEAL_MS, () => {
      g.round += 1;
      g.phase = 'pick';
      g.picks = [null, null];
      g.picked = [false, false];
      g.last = null;
      broadcast(g);
    });
  }

  /* ---------------------------------------------------------------- */
  /* Reaction Duel                                                     */
  /* ---------------------------------------------------------------- */

  function duelReady(g) {
    g.phase = 'ready';
    g.last = null;
    g.goAt = 0;
    setTimer(g, DUEL_READY_MS, () => duelWait(g));
  }

  function duelWait(g) {
    g.phase = 'wait';
    broadcast(g);
    const delay = randomInt(DUEL_WAIT_MIN_MS, DUEL_WAIT_MAX_MS + 1);
    setTimer(g, delay, () => duelGo(g));
  }

  function duelGo(g) {
    g.phase = 'go';
    g.goAt = now();
    broadcast(g);
    setTimer(g, DUEL_GO_TIMEOUT_MS, () => duelEnd(g, { winner: null, ms: null, reason: 'idle' }));
  }

  function duelEnd(g, last) {
    g.phase = 'reveal';
    g.last = last;
    if (last.winner !== null) g.scores[last.winner] += 1;

    if (last.winner !== null && g.scores[last.winner] >= g.target) {
      winBy(g, last.winner);
      return;
    }

    broadcast(g);
    setTimer(g, DUEL_REVEAL_MS, () => {
      if (last.winner !== null) g.round += 1; // a round nobody tapped in is played again
      duelReady(g);
      broadcast(g);
    });
  }

  function duelMove(g, userId) {
    const side = sideOf(g, userId);
    if (side < 0) return;

    if (g.phase === 'wait') {
      // Tapped before the signal: the point goes to the other player
      duelEnd(g, { winner: 1 - side, ms: null, reason: 'early' });
    } else if (g.phase === 'go') {
      // The server measures the time, so it is the same clock for both players
      duelEnd(g, { winner: side, ms: Math.max(0, now() - g.goAt), reason: 'tap' });
    }
    // Taps during "Get ready" and while the result is showing are ignored
  }

  /* ---------------------------------------------------------------- */
  /* What server.js calls                                              */
  /* ---------------------------------------------------------------- */

  // A new challenge: set up the public shape of the game. Nothing is secret yet.
  function init(g) {
    g.timer = null;
    g.scores = [0, 0];
    g.board = [];
    g.last = null;

    if (g.type === 'mem') {
      g.board = new Array(MEM_PAIRS * 2).fill(null); // null = face down, a number = the symbol face up
      g.owners = new Array(MEM_PAIRS * 2).fill(null); // who claimed each pair: 0, 1 or null
      g.deck = null; // the hidden symbols, filled in when the game starts
      g.flipped = [];
      g.lock = false;
      g.hit = null;
    } else if (g.type === 'rps') {
      g.target = RPS_TARGET;
      g.round = 1;
      g.phase = null;
      g.picks = [null, null]; // private until both have picked
      g.picked = [false, false];
    } else if (g.type === 'duel') {
      g.target = DUEL_TARGET;
      g.round = 1;
      g.phase = null;
      g.goAt = 0;
    }
  }

  // Someone accepted. The caller broadcasts afterwards.
  function start(g) {
    g.turn = null;
    if (g.type === 'mem') {
      const symbols = [];
      for (let i = 0; i < MEM_PAIRS; i++) symbols.push(i, i);
      g.deck = shuffled(symbols);
      g.turn = g.challenger.id;
    } else if (g.type === 'rps') {
      g.phase = 'pick';
    } else if (g.type === 'duel') {
      duelReady(g);
    }
  }

  function move(g, userId, index) {
    if (!g || g.status !== 'playing' || sideOf(g, userId) < 0) return;
    if (g.type === 'mem') memMove(g, userId, index);
    else if (g.type === 'rps') rpsMove(g, userId, index);
    else if (g.type === 'duel') duelMove(g, userId);
  }

  // The game is over or gone: stop its timers
  function stop(g) {
    if (g.timer) cancel(g.timer);
    g.timer = null;
  }

  // The extra fields the browser may see. The deck and the picks are never in here.
  function publicFields(g) {
    if (g.type === 'mem') {
      return { owners: g.owners, scores: g.scores, lock: g.lock, hit: g.hit };
    }
    if (g.type === 'rps') {
      return { scores: g.scores, round: g.round, phase: g.phase, picked: g.picked, last: g.last, target: g.target };
    }
    if (g.type === 'duel') {
      return { scores: g.scores, round: g.round, phase: g.phase, last: g.last, target: g.target };
    }
    return {};
  }

  return { isQuick, init, start, move, stop, publicFields };
}

module.exports = {
  createQuickGames,
  TYPES,
  MEM_PAIRS,
  MEM_HIDE_MS,
  RPS_TARGET,
  RPS_REVEAL_MS,
  DUEL_TARGET,
  DUEL_READY_MS,
  DUEL_GO_TIMEOUT_MS,
  DUEL_REVEAL_MS
};
