/**
 * KOR DA — SHARED SITE SHELL (shell.js)
 *
 * The single, canonical implementation of the Kor Da site chrome shared by
 * every inner page (property pages, explore, host, profile, info, legal).
 *
 *   KorDaShell
 *   ├── Navbar          (desktop nav + logo + actions + hamburger)
 *   ├── Drawer          (slide-in mobile menu)
 *   ├── MobileNav       (bottom tab bar)
 *   ├── ProfileSheet    (bottom profile/menu sheet)
 *   ├── Footer          (site footer)
 *   ├── Toast           (#toast container for utils.js)
 *   └── ListingModals   (property detail / image zoom / booking modals)
 *
 * This module only renders markup. All interaction behavior (scroll state,
 * drawer open/close, sheet open/close) lives in navigation.js, which must be
 * loaded AFTER this file so the elements exist when it wires up.
 *
 * Markup is intentionally identical to the approved Kor Da homepage UI.
 * No redesign is performed here.
 */
(function(){
  'use strict';

  function cfg() {
    return window.KORDA_CONFIG || {
      phoneDisplay: '0315-5881733',
      waNumber: '923155881733',
      siteName: 'Kor Da',
      email: 'kordapakistan@gmail.com'
    };
  }

  function waHref() {
    return 'https://wa.me/' + cfg().waNumber;
  }

  /* ── NAVBAR (desktop nav + hamburger) ─────────────────────────────── */
  function navbarHTML() {
    return '' +
      '<nav id="nav" role="navigation" aria-label="Main navigation">' +
        '<a href="/" class="nlogo" aria-label="Kor Da Home">' +
          '<div class="nmark"><svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white"/><circle cx="10" cy="9" r="2" fill="#E9A825"/></svg></div>' +
          '<span class="nname">Kor Da</span>' +
        '</a>' +
        '<div class="nlinks" role="menubar">' +
          '<a href="/explore/" class="nl">Explore</a>' +
          '<a href="/how-it-works/" class="nl">How it Works</a>' +
          '<a href="/about/" class="nl">About</a>' +
          '<a href="/help/" class="nl">Help</a>' +
          '<a href="/contact/" class="nl">Contact</a>' +
        '</div>' +
        '<div class="nacts">' +
          '<a href="' + waHref() + '" target="_blank" rel="noopener" class="nsoc" aria-label="WhatsApp">&#128172;</a>' +
          '<a href="/host/" class="nhost">List Property</a>' +
        '</div>' +
        '<button class="nhbg" id="nhbg" aria-label="Open menu" aria-expanded="false">' +
          '<span></span><span></span><span></span>' +
        '</button>' +
      '</nav>';
  }

  /* ── DRAWER (slide-in menu) ───────────────────────────────────────── */
  function drawerHTML() {
    return '' +
      '<div class="novl" id="novl" aria-hidden="true"></div>' +
      '<div class="ndr" id="ndr" role="dialog" aria-label="Navigation">' +
        '<button class="ndx" id="ndx" aria-label="Close menu">&#x2715;</button>' +
        '<a href="/explore/" class="ndl">&#128269; Explore Stays</a>' +
        '<a href="/how-it-works/" class="ndl">&#128203; How it Works</a>' +
        '<a href="/safety/" class="ndl">&#128274; Safety &amp; Trust</a>' +
        '<a href="/about/" class="ndl">&#128100; About</a>' +
        '<a href="/help/" class="ndl">&#10067; Help / FAQ</a>' +
        '<a href="/contact/" class="ndl">&#9993;&#65039; Contact</a>' +
        '<div class="ndiv"></div>' +
        '<a href="/host/" class="ndl">&#127968; List Your Property</a>' +
        '<a href="/host/dashboard/" class="ndl">&#128202; Host Dashboard</a>' +
        '<div class="ndiv"></div>' +
        '<a href="' + waHref() + '" target="_blank" rel="noopener" class="btn btn-p" style="margin-top:10px;justify-content:center">&#128172; WhatsApp Support</a>' +
      '</div>';
  }

  /* ── MOBILE BOTTOM NAV ────────────────────────────────────────────── */
  function mobileNavHTML() {
    return '' +
      '<nav class="mnav" id="mnav" aria-label="Mobile navigation">' +
        '<a href="/explore/" class="mnav-i on" data-sec="listings" aria-label="Explore">' +
          '<span class="mnav-ic" aria-hidden="true">&#128269;</span>' +
          '<span class="mnav-lb">Explore</span>' +
        '</a>' +
        '<a href="/host/" class="mnav-i" data-sec="host-form" aria-label="Host">' +
          '<span class="mnav-ic" aria-hidden="true">&#127968;</span>' +
          '<span class="mnav-lb">Host</span>' +
        '</a>' +
        '<a href="/about/" class="mnav-i" data-sec="about" aria-label="About">' +
          '<span class="mnav-ic" aria-hidden="true">&#9432;</span>' +
          '<span class="mnav-lb">About</span>' +
        '</a>' +
        '<button type="button" class="mnav-i" id="mnavProfileBtn" aria-label="Profile" aria-haspopup="dialog" aria-controls="msheet" aria-expanded="false">' +
          '<span class="mnav-ic" aria-hidden="true">&#128100;</span>' +
          '<span class="mnav-lb">Profile</span>' +
        '</button>' +
      '</nav>';
  }

  /* ── PROFILE / MENU SHEET ─────────────────────────────────────────── */
  function profileSheetHTML() {
    return '' +
      '<div class="moverlay" id="moverlay" aria-hidden="true"></div>' +
      '<div class="msheet" id="msheet" role="dialog" aria-modal="true" aria-label="Profile">' +
        '<div class="msheet-bar" aria-hidden="true"></div>' +
        '<div class="msheet-h">' +
          '<span class="msheet-t">Profile</span>' +
          '<button type="button" class="msheet-x" id="msheetX" aria-label="Close profile">&#10005;</button>' +
        '</div>' +
        '<div class="msheet-b">' +
          '<div class="mpf">' +
            '<div class="mpf-av" aria-hidden="true">&#128100;</div>' +
            '<div class="mpf-m">' +
              '<div class="mpf-n">Guest</div>' +
              '<div class="mpf-s">Sign in to save stays &amp; manage bookings</div>' +
            '</div>' +
            '<a href="/login/" class="btn btn-p btn-sm">Sign In</a>' +
          '</div>' +
          '<div class="msg">' +
            '<div class="msl">My Kor Da</div>' +
            '<a href="/profile/saved/" class="msi">&#9825; Saved Stays</a>' +
            '<a href="/profile/bookings/" class="msi">&#128197; My Trips</a>' +
            '<a href="/messages/" class="msi">&#128172; Messages</a>' +
            '<a href="/host/" class="msi">&#127968; Become a Host</a>' +
          '</div>' +
          '<div class="msg">' +
            '<div class="msl">Support</div>' +
            '<a href="/help/" class="msi">&#10067; Help Center</a>' +
            '<a href="' + waHref() + '" target="_blank" rel="noopener" class="msi">&#128172; WhatsApp Support</a>' +
            '<a href="/contact/" class="msi">&#9993;&#65039; Contact Us</a>' +
          '</div>' +
          '<div class="msg">' +
            '<div class="msl">Settings &amp; Legal</div>' +
            '<a href="/profile/settings/" class="msi">&#9881;&#65039; Settings</a>' +
            '<a href="/privacy.html" class="msi">Privacy Policy</a>' +
            '<a href="/terms.html" class="msi">Terms &amp; Conditions</a>' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  /* ── FOOTER ───────────────────────────────────────────────────────── */
  function footerHTML() {
    var c = cfg();
    var wa = c.phoneDisplay || '0315-5881733';
    var em = c.email || 'kordapakistan@gmail.com';
    return '' +
      '<footer class="kd-footer" role="contentinfo">' +
        '<div class="wrap">' +
          '<div class="kd-f-top">' +
            '<div class="kd-f-brand">' +
              '<div class="nmark" aria-hidden="true"><svg viewBox="0 0 20 20" fill="none"><path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white"/><circle cx="10" cy="9" r="2" fill="#E9A825"/></svg></div>' +
              '<span class="kd-f-name">Kor Da</span>' +
            '</div>' +
            '<p class="kd-f-tag">Pakistan&rsquo;s verified home rental platform. CNIC-verified hosts &middot; PKR pricing &middot; WhatsApp booking.</p>' +
          '</div>' +
          '<nav class="kd-f-links" aria-label="Footer">' +
            '<a href="/explore/">Explore</a>' +
            '<a href="/how-it-works/">How it Works</a>' +
            '<a href="/host/">Host</a>' +
            '<a href="/about/">About</a>' +
            '<a href="/safety/">Safety</a>' +
            '<a href="/help/">Help</a>' +
            '<a href="/contact/">Contact</a>' +
          '</nav>' +
          '<nav class="kd-f-links kd-f-legal" aria-label="Legal">' +
            '<a href="/privacy.html">Privacy</a>' +
            '<a href="/terms.html">Terms</a>' +
            '<a href="/cancellation.html">Cancellation</a>' +
            '<a href="/refund-policy.html">Refund Policy</a>' +
          '</nav>' +
          '<p class="kd-f-contact">WhatsApp ' + wa + ' &middot; EasyPaisa 03495620844 &middot; ' + em + '</p>' +
          '<div class="kd-f-bot">' +
            '<span>&copy; 2025&ndash;2026 Kor Da (Pvt.) Ltd. &middot; Havelian, KPK, Pakistan</span>' +
          '</div>' +
        '</div>' +
      '</footer>';
  }

  /* ── LISTING MODALS (property detail / zoom / booking) ────────────── */
  /* Only injected on pages that render PropertyCard. Identical to the
     homepage modal containers so property.js can fill them unchanged. */
  function listingModalsHTML() {
    return '' +
      '<div class="modal-bg" id="pdModal" role="dialog" aria-label="Property details" aria-modal="true">' +
        '<div class="modal-box" id="pdModalBody" onclick="event.stopPropagation()"></div>' +
      '</div>' +
      '<div class="imgzoom-bg" id="imgZoom" role="dialog" aria-label="Zoom image">' +
        '<button class="imgzoom-close" onclick="closeImgZoom()" aria-label="Close zoom">&times;</button>' +
        '<span class="imgzoom-count" id="imgZoomCount"></span>' +
        '<button class="imgzoom-arrow imgzoom-prev" id="imgZoomPrev" onclick="slideImg(-1)" aria-label="Previous image">&#10094;</button>' +
        '<img id="imgZoomEl" class="imgzoom-el" onclick="event.stopPropagation()" alt="Zoomed photo">' +
        '<button class="imgzoom-arrow imgzoom-next" id="imgZoomNext" onclick="slideImg(1)" aria-label="Next image">&#10095;</button>' +
        '<div class="imgzoom-hint">Scroll/pinch to zoom &middot; Swipe or arrows to browse &middot; Tap outside to close</div>' +
      '</div>' +
      '<div class="modal-bg" id="bkModal" role="dialog" aria-label="Book this property" aria-modal="true">' +
        '<div class="modal-box bk-box" id="bkModalBody">' +
          '<button class="modal-close" onclick="closeBkModal()" aria-label="Close">&times;</button>' +
          '<div class="bk-prop-info" id="bkPropInfo"></div>' +
          '<div class="bk-form">' +
            '<div class="bk-fields">' +
              '<div class="bk-col">' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkName">Full Name *</label><input type="text" class="bk-inp" id="bkName" placeholder="Muhammad Ali" autocomplete="name"></div>' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkPhone">WhatsApp Number *</label><input type="tel" class="bk-inp" id="bkPhone" placeholder="+92 3XX XXX XXXX" autocomplete="tel"></div>' +
              '</div>' +
              '<div class="bk-dates">' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkCheckIn">Check-in *</label><input type="date" class="bk-inp" id="bkCheckIn"></div>' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkCheckOut">Check-out *</label><input type="date" class="bk-inp" id="bkCheckOut"></div>' +
              '</div>' +
              '<div id="bkNights" class="bk-nights"></div>' +
              '<div class="bk-col">' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkGuests">Guests *</label><select class="bk-inp" id="bkGuests"><option>1</option><option>2</option><option selected>3</option><option>4</option><option>5</option><option>6</option><option>8</option><option>10+</option></select></div>' +
                '<div class="bk-fg"><label class="bk-lbl" for="bkArrival">Arrival Time</label><select class="bk-inp" id="bkArrival"><option value="">Flexible</option><option>Morning</option><option>Afternoon</option><option>Evening</option></select></div>' +
              '</div>' +
              '<div class="bk-fg"><label class="bk-lbl" for="bkRequests">Special Requests</label><textarea class="bk-inp bk-ta" id="bkRequests" placeholder="e.g. late check-in, need parking &amp; WiFi, ground floor, extra mattress, airport pickup"></textarea></div>' +
            '</div>' +
            '<div class="bk-cost" id="bkCost"></div>' +
            '<button class="btn btn-p btn-xl" id="bkSubmit" onclick="submitBooking()" style="width:100%;justify-content:center">&#128172; Send Booking Request</button>' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  /* ── MOUNT ────────────────────────────────────────────────────────── */
  function ensureToast() {
    if (!document.getElementById('toast')) {
      var t = document.createElement('div');
      t.id = 'toast';
      t.setAttribute('role', 'status');
      t.setAttribute('aria-live', 'polite');
      document.body.appendChild(t);
    }
  }

  function mount(opts) {
    opts = opts || {};
    var navEl = document.getElementById('kd-nav');
    var footEl = document.getElementById('kd-footer');

    if (navEl) {
      navEl.innerHTML = navbarHTML() + drawerHTML() + mobileNavHTML() + profileSheetHTML();
    }
    if (footEl) {
      footEl.innerHTML = footerHTML();
    }
    ensureToast();
    if (opts.modals) {
      var holder = document.getElementById('kd-modals');
      if (holder) holder.innerHTML = listingModalsHTML();
      else document.body.insertAdjacentHTML('beforeend', listingModalsHTML());
    }
  }

  window.KorDaShell = {
    mount: mount,
    navbarHTML: navbarHTML,
    footerHTML: footerHTML,
    listingModalsHTML: listingModalsHTML
  };

  /* Auto-mount on DOMContentLoaded so pages only need the containers. */
  function boot() { mount(window.KD_SHELL_OPTS || {}); }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
