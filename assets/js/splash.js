/**
 * KOR DA — SPLASH SCREEN (splash.js)
 * Full-screen branded launch for the installed PWA (standalone mode):
 * background slideshow + Ken Burns, tagline, loader dots, minimum visible
 * time, smooth fade into the homepage. Local previews (file://, localhost)
 * skip the splash entirely. Reduced motion -> static branded background.
 */
'use strict';

(function () {
  var el = document.getElementById('splash');
  if (!el) return;

  var MIN_VIS = 1800; /* min ms once the first slide is rendered */
  var CAP_MS = 4000;  /* hard ceiling before revealing the page */
  var IMGS = ['splash-1.jpg', 'splash-2.jpg', 'splash-3.jpg', 'splash-4.jpg', 'splash-5.jpg'];

  var isStandalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
  var isTest = /[?&]splash=1/.test(window.location.search);
  var isFile = window.location.protocol === 'file:';
  var host = window.location.hostname;
  var isLocal = isFile || host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);

  if (isLocal && !isTest) return;      /* local previews: go straight to the homepage */
  if (!isStandalone && !isTest) return; /* splash only for the installed app */

  el.hidden = false;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    el.classList.add('noanim');
  }
  el.setAttribute('aria-hidden', 'false');

  var start = Date.now();
  var done = false;
  var firstReady = false;

  var box = document.getElementById('splashSlides');
  if (box) {
    for (var i = 0; i < IMGS.length; i++) {
      var s = document.createElement('div');
      s.className = 'ss';
      if (i === 0) s.style.opacity = '1'; /* first slide paints the instant its image is cached */
      s.style.backgroundImage = 'url(assets/images/splash/' + IMGS[i] + ')';
      box.appendChild(s);
    }
    var warm = new Image();
    warm.onload = function () {
      firstReady = true;
      scheduleExit(start + MIN_VIS);
    };
    warm.src = 'assets/images/splash/' + IMGS[0];
  }

  function finish() {
    if (done) return;
    done = true;
    el.classList.add('done');
    setTimeout(function () {
      el.style.display = 'none';
      el.setAttribute('aria-hidden', 'true');
    }, 700);
  }

  function scheduleExit(ms) {
    if (done) return;
    var wait = ms - Date.now();
    setTimeout(finish, wait > 0 ? wait : 0);
  }

  window.addEventListener('load', function () {
    scheduleExit(firstReady ? start + MIN_VIS : start + 1000);
  });

  scheduleExit(start + CAP_MS);
})();
