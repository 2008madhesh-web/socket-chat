(function () {
  'use strict';

  var root = document.documentElement;
  var EMAIL = '2008madhesh@gmail.com';

  /* ---------- light / dark, shared with the app ---------- */
  var themeBtn = document.getElementById('theme-toggle');
  function themeLabel() {
    themeBtn.textContent = root.getAttribute('data-theme') === 'light' ? 'Dark mode' : 'Light mode';
  }
  if (themeBtn) {
    themeLabel();
    themeBtn.addEventListener('click', function () {
      var toLight = root.getAttribute('data-theme') !== 'light';
      if (toLight) root.setAttribute('data-theme', 'light');
      else root.removeAttribute('data-theme');
      try { localStorage.setItem('atti-theme', toLight ? 'light' : 'dark'); } catch (e) { /* storage blocked */ }
      themeLabel();
    });
  }

  /* ---------- table of contents, built from the section headings ---------- */
  var doc = document.querySelector('.doc[data-toc]');
  var rail = document.getElementById('toc-rail');
  var fold = document.getElementById('toc-fold');
  if (doc && (rail || fold)) {
    var heads = Array.prototype.slice.call(doc.querySelectorAll('h2[id]'));
    var fill = function (host) {
      var ul = document.createElement('ul');
      ul.className = 'toc-list';
      heads.forEach(function (h) {
        var li = document.createElement('li');
        var a = document.createElement('a');
        a.href = '#' + h.id;
        a.textContent = h.textContent;
        li.appendChild(a);
        ul.appendChild(li);
      });
      host.appendChild(ul);
      return ul;
    };
    var railList = rail ? fill(rail) : null;
    if (fold) fill(fold);

    // Mark the section being read
    if (railList && 'IntersectionObserver' in window) {
      var links = {};
      Array.prototype.forEach.call(railList.querySelectorAll('a'), function (a) { links[a.getAttribute('href').slice(1)] = a; });
      var current = null;
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) { if (en.isIntersecting) current = en.target.id; });
        Object.keys(links).forEach(function (id) {
          if (id === current) links[id].setAttribute('aria-current', 'true');
          else links[id].removeAttribute('aria-current');
        });
      }, { rootMargin: '0px 0px -70% 0px' });
      heads.forEach(function (h) { io.observe(h); });
    }
  }

  /* ---------- contact: copy the address, or open the message in the person's email app ---------- */
  var note = document.getElementById('copy-note');
  var copyBtn = document.getElementById('copy-mail');
  function say(text) {
    if (!note) return;
    note.textContent = text;
  }
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var done = function (ok) { say(ok ? 'Address copied.' : 'Could not copy. Select the address above and copy it.'); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(EMAIL).then(function () { done(true); }, function () { done(false); });
      } else {
        done(false);
      }
    });
  }

  var form = document.getElementById('mail-form');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var topic = form.elements.topic.value;
      var message = form.elements.message.value.trim();
      var hint = document.getElementById('form-hint');
      if (!message) {
        hint.textContent = 'Write your message first.';
        form.elements.message.focus();
        return;
      }
      hint.textContent = 'Your email app should open with the message ready to send. If it does not, copy the address above.';
      var subject = 'Atti chat: ' + topic;
      var body = message + '\n\nSent from the Atti chat contact page';
      window.location.href = 'mailto:' + EMAIL + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
    });
  }
})();
