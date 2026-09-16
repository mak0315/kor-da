/**
 * KOR DA — CHECKOUT PAGE (checkout.js)
 *
 * Controller for /checkout. Reads the property id from the query string
 * (?property=<id|slug>), loads it through PropertyService, renders the
 * booking summary + guest form, validates input, and confirms the request.
 *
 * Persistence is currently local (localStorage, key: "kd_bookings") behind
 * submitCheckoutAPI() so a real booking API / payment gateway can be wired
 * in later by replacing that single function — no UI changes required.
 *
 * No WhatsApp handoff happens here by design.
 */
(function(){
  'use strict';

  var CONFIG = window.KORDA_CONFIG || {
    siteName: 'Kor Da',
    siteUrl: 'https://www.kordaa.com'
  };

  var STORAGE_KEY = 'kd_bookings';
  var state = { prop: null, nights: 0, total: 0 };

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[<>&"']/g, function(c) {
      return { '<':'&lt;', '>':'&gt;', '&':'&amp;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }

  function fmt(n) {
    var v = parseInt(n, 10);
    return isNaN(v) ? '0' : v.toLocaleString('en-PK');
  }

  function toastw(msg, type) {
    if (typeof window.toast === 'function') window.toast(msg, type || 'warn');
  }

  function v(id) {
    var el = $(id);
    return el ? (el.value || '').trim() : '';
  }

  function setText(id, txt) {
    var el = $(id);
    if (el) el.textContent = txt;
  }

  function qs(name) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : '';
  }

  function pad(n) { return String(n).length < 2 ? '0' + n : String(n); }

  function isoFromDate(d) {
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  function todayISO(offsetDays) {
    var d = new Date();
    d.setDate(d.getDate() + (offsetDays || 0));
    return isoFromDate(d);
  }

  function validDate(str) {
    if (!str || !/^\d{4}-\d{2}-\d{2}$/.test(str)) return '';
    var d = new Date(str + 'T00:00:00');
    if (isNaN(d.getTime())) return '';
    return isoFromDate(d) === str ? str : '';
  }

  function addDays(str, n) {
    var d = new Date(str + 'T00:00:00');
    if (isNaN(d.getTime())) return '';
    d.setDate(d.getDate() + n);
    return isoFromDate(d);
  }

  function formatDate(iso) {
    if (!iso) return '—';
    var d = new Date(iso + 'T00:00:00');
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  }

  function nightsBetween(a, b) {
    if (!a || !b) return 0;
    var x = new Date(a + 'T00:00:00'), y = new Date(b + 'T00:00:00');
    return Math.max(0, Math.round((y - x) / 86400000));
  }

  function genReference() {
    var d = new Date();
    var date = d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate());
    var rand = Math.random().toString(36).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 4);
    return 'KD-' + date + '-' + (rand || '0000');
  }

  function propImage(prop) {
    if (prop.image) return prop.image;
    if (Array.isArray(prop.gallery) && prop.gallery[0]) return prop.gallery[0];
    return 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=80';
  }

  function propLocation(prop) {
    return prop.address || [prop.area, prop.city].filter(Boolean).join(', ') || 'Islamabad';
  }

  /* ── PERSISTENCE (swap body for a real API later) ─────────────────── */

  function submitCheckoutAPI(record) {
    return new Promise(function(resolve) {
      /* Future: POST record to /api/bookings and resolve with the server
         reference + payment intent. For now we persist locally. */
      try {
        var list = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
        if (!Array.isArray(list)) list = [];
        list.unshift(record);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
      } catch (e) {
        console.warn('Checkout: could not persist booking locally', e);
      }
      resolve({ ok: true, reference: record.reference });
    });
  }

  /* ── RENDER: NOT FOUND ────────────────────────────────────────────── */

  function renderNotFound() {
    document.title = 'Property not found | ' + CONFIG.siteName;
    return '<section class="pg-hero"><div class="pg-hero-in">' +
             '<div class="pg-eyebrow"><span class="lbl">Checkout</span></div>' +
             '<h1>Property not found</h1>' +
             '<p class="pg-sub">We could not find the stay you are trying to book.</p>' +
           '</div></section>' +
           '<section class="sec"><div class="wrap ck-wrap"><div class="kd-empty">' +
             '<div class="kd-empty-ic" aria-hidden="true">&#128269;</div>' +
             '<h3>Stay unavailable</h3>' +
             '<p>This property may have been removed or is no longer accepting bookings.</p>' +
             '<div class="kd-empty-acts"><a class="btn btn-p" href="/explore/">Explore Stays</a></div>' +
           '</div></div></section>';
  }

  /* ── RENDER: CHECKOUT FORM ────────────────────────────────────────── */

  function guestOptions(maxGuests) {
    var max = parseInt(maxGuests, 10) > 0 ? parseInt(maxGuests, 10) : 10;
    var html = '';
    for (var i = 1; i <= max; i++) html += '<option value="' + i + '">' + i + '</option>';
    return html;
  }

  function renderCheckout(prop) {
    var title = prop.title || prop.type || 'Property';
    var loc = propLocation(prop);
    var img = propImage(prop);

    return '<section class="pg-hero"><div class="pg-hero-in">' +
             '<div class="pg-eyebrow"><span class="lbl">Secure Checkout</span></div>' +
             '<h1>Complete Your Booking</h1>' +
             '<p class="pg-sub">Review your stay, add your details, and confirm your reservation.</p>' +
           '</div></section>' +
           '<section class="sec-sm" style="padding-top:clamp(24px,4vw,44px);padding-bottom:clamp(40px,6vw,72px)">' +
             '<div class="wrap ck-wrap"><div class="ck-grid">' +
               '<div class="ck-card">' +
                 '<h2 class="ck-card-h">Guest details</h2>' +
                 '<p class="ck-card-s">Fields marked * are required to confirm your booking.</p>' +
                 '<form class="ck-fields" id="ckForm" novalidate>' +
                   '<div class="ck-fg">' +
                     '<label class="ck-lbl" for="ckName">Full Name *</label>' +
                     '<input class="ck-inp" type="text" id="ckName" name="name" placeholder="Muhammad Ali" autocomplete="name">' +
                     '<span class="ck-err">Please enter your full name.</span>' +
                   '</div>' +
                   '<div class="ck-fg">' +
                     '<label class="ck-lbl" for="ckEmail">Email *</label>' +
                     '<input class="ck-inp" type="email" id="ckEmail" name="email" placeholder="you@example.com" autocomplete="email">' +
                     '<span class="ck-err">Please enter a valid email address.</span>' +
                   '</div>' +
                   '<div class="ck-fg">' +
                     '<label class="ck-lbl" for="ckPhone">Phone *</label>' +
                     '<input class="ck-inp" type="tel" id="ckPhone" name="phone" placeholder="+92 3XX XXX XXXX" autocomplete="tel">' +
                     '<span class="ck-err">Please enter your phone number.</span>' +
                   '</div>' +
                   '<div class="ck-col">' +
                     '<div class="ck-fg">' +
                       '<label class="ck-lbl" for="ckCheckIn">Check-in *</label>' +
                       '<input class="ck-inp" type="date" id="ckCheckIn" name="checkin">' +
                       '<span class="ck-err">Please select a check-in date.</span>' +
                     '</div>' +
                     '<div class="ck-fg">' +
                       '<label class="ck-lbl" for="ckCheckOut">Check-out *</label>' +
                       '<input class="ck-inp" type="date" id="ckCheckOut" name="checkout">' +
                       '<span class="ck-err">Check-out must be after check-in.</span>' +
                     '</div>' +
                   '</div>' +
                   '<div class="ck-fg">' +
                     '<label class="ck-lbl" for="ckGuests">Guests *</label>' +
                     '<select class="ck-inp" id="ckGuests" name="guests">' + guestOptions(prop.maxGuests) + '</select>' +
                     '<span class="ck-err">Please select a valid number of guests.</span>' +
                   '</div>' +
                   '<button type="submit" class="btn btn-p btn-xl" id="ckSubmit" style="width:100%;justify-content:center;margin-top:6px">Complete Checkout</button>' +
                 '</form>' +
               '</div>' +
               '<aside class="ck-side"><div class="ck-card">' +
                 '<h2 class="ck-card-h">Booking summary</h2>' +
                 '<div class="ck-prop" style="margin-top:14px">' +
                   '<img class="ck-prop-img" src="' + esc(img) + '" alt="' + esc(title) + '">' +
                   '<div><div class="ck-prop-t">' + esc(title) + '</div>' +
                   '<div class="ck-prop-l">&#128205; ' + esc(loc) + '</div></div>' +
                 '</div>' +
                 '<div class="ck-line"><span>Price per night</span><strong>PKR ' + fmt(prop.price) + '</strong></div>' +
                 '<div class="ck-line"><span>Check-in</span><strong id="ckrIn">—</strong></div>' +
                 '<div class="ck-line"><span>Check-out</span><strong id="ckrOut">—</strong></div>' +
                 '<div class="ck-line"><span>Nights</span><strong id="ckrNights">—</strong></div>' +
                 '<div class="ck-line"><span>Guests</span><strong id="ckrGuests">—</strong></div>' +
                 '<div class="ck-div"></div>' +
                 '<div class="ck-total"><span>Total</span><span id="ckrTotal">PKR 0</span></div>' +
                 '<div class="ck-note">Final amount confirmed by the host before payment.</div>' +
                 '<div class="ck-secure">&#128274; Your details are kept private</div>' +
               '</div></aside>' +
             '</div></div>' +
           '</section>';
  }

  /* ── LIVE SUMMARY ─────────────────────────────────────────────────── */

  function updateSummary() {
    var prop = state.prop;
    if (!prop) return;
    var inV = v('ckCheckIn'), outV = v('ckCheckOut');
    var nights = nightsBetween(inV, outV);
    state.nights = nights;
    state.total = nights * (parseInt(prop.price, 10) || 0);

    setText('ckrIn', formatDate(inV));
    setText('ckrOut', formatDate(outV));
    setText('ckrNights', nights > 0 ? nights : '—');
    setText('ckrGuests', v('ckGuests') || '—');
    setText('ckrTotal', state.total > 0 ? 'PKR ' + fmt(state.total) : 'PKR 0');
  }

  /* ── VALIDATION ───────────────────────────────────────────────────── */

  function setBad(id, isBad) {
    var el = $(id);
    var fg = el ? el.closest('.ck-fg') : null;
    if (fg) fg.classList.toggle('bad', !!isBad);
  }

  function validate(data) {
    var prop = state.prop;
    var maxG = prop ? (parseInt(prop.maxGuests, 10) || 10) : 10;
    var ok = true, firstBad = null;

    function check(id, isBad) {
      setBad(id, isBad);
      if (isBad) { ok = false; if (!firstBad) firstBad = id; }
    }

    check('ckName', !data.fullName);
    check('ckEmail', !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email));
    check('ckPhone', !data.phone || data.phone.replace(/[^0-9]/g, '').length < 7);
    check('ckCheckIn', !data.checkIn);
    check('ckCheckOut', !data.checkOut || (!!data.checkIn && data.checkOut <= data.checkIn));
    check('ckGuests', !data.guests || data.guests < 1 || data.guests > maxG);

    if (!ok) {
      toastw('Please correct the highlighted fields', 'warn');
      var el = firstBad ? $(firstBad) : null;
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return ok;
  }

  /* ── SUBMIT ───────────────────────────────────────────────────────── */

  function handleSubmit(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    var prop = state.prop;
    if (!prop) return;

    var data = {
      fullName: v('ckName'),
      email: v('ckEmail'),
      phone: v('ckPhone'),
      checkIn: v('ckCheckIn'),
      checkOut: v('ckCheckOut'),
      guests: parseInt(v('ckGuests'), 10) || 0
    };
    if (data.checkIn && data.checkOut && data.checkOut <= data.checkIn) {
      toastw('Check-out must be after check-in', 'warn');
    }
    if (!validate(data)) return;

    var nights = nightsBetween(data.checkIn, data.checkOut);
    var record = {
      reference: genReference(),
      propertyId: prop.id || prop.slug,
      propertySlug: prop.slug || prop.id,
      propertyTitle: prop.title || prop.type || 'Property',
      propertyLocation: propLocation(prop),
      pricePerNight: parseInt(prop.price, 10) || 0,
      checkIn: data.checkIn,
      checkOut: data.checkOut,
      nights: nights,
      guests: data.guests,
      fullName: data.fullName,
      email: data.email,
      phone: data.phone,
      total: nights * (parseInt(prop.price, 10) || 0),
      status: 'pending',
      createdAt: new Date().toISOString()
    };

    var btn = $('ckSubmit');
    if (btn) { btn.disabled = true; btn.textContent = 'Submitting…'; }

    submitCheckoutAPI(record).then(function(res) {
      renderSuccess(record, res && res.reference);
    }).catch(function(err) {
      console.warn('Checkout: submission failed', err);
      if (btn) { btn.disabled = false; btn.textContent = 'Complete Checkout'; }
      toastw('Something went wrong. Please try again.', 'err');
    });
  }

  /* ── RENDER: SUCCESS ──────────────────────────────────────────────── */

  function line(label, val) {
    return '<div class="ck-line"><span>' + esc(label) + '</span><strong>' + esc(val) + '</strong></div>';
  }

  function renderSuccess(record, reference) {
    var root = $('ck-root');
    if (!root) return;
    var ref = reference || record.reference;

    root.innerHTML = '<section class="pg-hero"><div class="pg-hero-in">' +
        '<div class="pg-eyebrow"><span class="lbl">Booking Confirmed</span></div>' +
        '<h1>Booking Confirmed</h1>' +
        '<p class="pg-sub">Thank you, ' + esc(record.fullName.split(' ')[0] || '') + '. Your request is in.</p>' +
      '</div></section>' +
      '<section class="sec"><div class="wrap ck-wrap"><div class="ck-success">' +
        '<div class="ck-tick" aria-hidden="true">&#10003;</div>' +
        '<h2>Checked Out &#10003;</h2>' +
        '<p class="ck-lead">Your booking request has been successfully submitted.</p>' +
        '<div class="ck-ref">Reference: ' + esc(ref) + '</div>' +
        '<div class="ck-sumbox">' +
          '<h3 class="ck-card-h">Booking details</h3>' +
          line('Property', record.propertyTitle) +
          line('Location', record.propertyLocation) +
          line('Guest name', record.fullName) +
          line('Email', record.email) +
          line('Phone', record.phone) +
          line('Check-in', formatDate(record.checkIn)) +
          line('Check-out', formatDate(record.checkOut)) +
          line('Nights', record.nights) +
          line('Guests', record.guests) +
          '<div class="ck-div"></div>' +
          line('Total', 'PKR ' + fmt(record.total)) +
        '</div>' +
        '<div class="ck-acts">' +
          '<a class="btn btn-p" href="/explore/">Explore More Stays</a>' +
          '<a class="btn btn-o" href="/">Back to Home</a>' +
        '</div>' +
      '</div></div></section>';

    document.title = 'Booking Confirmed | ' + CONFIG.siteName;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* ── WIRE UP ──────────────────────────────────────────────────────── */

  function wireCheckout(prop) {
    var maxG = parseInt(prop.maxGuests, 10) || 10;
    var today = todayISO(0), tomorrow = todayISO(1);

    var gSel = $('ckGuests');
    if (gSel) {
      var prefG = parseInt(qs('guests'), 10);
      gSel.value = (prefG >= 1 && prefG <= maxG) ? String(prefG) : '1';
      gSel.addEventListener('change', updateSummary);
    }

    var tIn = $('ckCheckIn'), tOut = $('ckCheckOut');
    if (tIn) {
      tIn.min = today;
      tIn.value = validDate(qs('checkin'));
    }
    if (tOut) {
      tOut.min = tomorrow;
      tOut.value = validDate(qs('checkout'));
    }
    if (tIn && tOut) {
      tIn.addEventListener('change', function() {
        var next = tIn.value ? addDays(tIn.value, 1) : tomorrow;
        tOut.min = next;
        if (tOut.value && tIn.value && tOut.value <= tIn.value) tOut.value = '';
        updateSummary();
      });
      tOut.addEventListener('change', function() {
        if (tOut.value && tIn.value && tOut.value <= tIn.value) {
          tOut.value = '';
          toastw('Check-out must be after check-in', 'warn');
        }
        updateSummary();
      });
    }

    ['ckName', 'ckEmail', 'ckPhone', 'ckGuests', 'ckCheckIn', 'ckCheckOut'].forEach(function(id) {
      var el = $(id);
      if (el) el.addEventListener('input', function() {
        var fg = el.closest('.ck-fg');
        if (fg) fg.classList.remove('bad');
      });
    });

    var form = $('ckForm');
    if (form) form.addEventListener('submit', handleSubmit);

    updateSummary();
  }

  /* ── INIT ─────────────────────────────────────────────────────────── */

  function init() {
    var root = $('ck-root');
    if (!root) return;

    var slug = qs('property') || qs('slug') || qs('id');
    if (!slug || !window.PropertyService) { root.innerHTML = renderNotFound(); return; }

    document.title = 'Checkout | ' + CONFIG.siteName;

    PropertyService.getBySlug(slug).then(function(prop) {
      if (!prop) { root.innerHTML = renderNotFound(); return; }
      state.prop = prop;
      root.innerHTML = renderCheckout(prop);
      wireCheckout(prop);
    }).catch(function() {
      root.innerHTML = renderNotFound();
    });
  }

  /* Public hooks — kept minimal so a backend can be attached later. */
  window.submitCheckout = handleSubmit;
  window.Checkout = { submit: submitCheckoutAPI };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
