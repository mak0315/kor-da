/**
 * KOR DA — INSTANT MULTI-CRITERIA SEARCH (search.js)
 * Modular: collect → validate → calculate → build message → submit
 * Data collection separated from submission for future API swap.
 */
(function(){
  'use strict';

  /* ── HELPERS ────────────────────────────────────────────────────── */

  function val(id) {
    var el = document.getElementById(id);
    return el ? (el.value || '').trim() : '';
  }

  function setErr(id, bad) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('err', bad);
  }

  function formatDate(dateStr) {
    if (!dateStr) return '';
    var d = new Date(dateStr + 'T00:00:00');
    var months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    return d.getDate() + ' ' + months[d.getMonth()] + ' ' + d.getFullYear();
  }

  /* ── NIGHTS CALCULATION ─────────────────────────────────────────── */

  function calculateNights(checkIn, checkOut) {
    if (!checkIn || !checkOut) return 0;
    var a = new Date(checkIn + 'T00:00:00');
    var b = new Date(checkOut + 'T00:00:00');
    var diff = Math.round((b - a) / (1000 * 60 * 60 * 24));
    return diff > 0 ? diff : 0;
  }

  function updateNightsDisplay() {
    var checkIn = val('hIn');
    var checkOut = val('hOut');
    var el = document.getElementById('hNights');
    if (!el) return;
    var nights = calculateNights(checkIn, checkOut);
    if (nights > 0) {
      el.textContent = nights + ' Night' + (nights > 1 ? 's' : '');
      el.style.display = 'block';
    } else {
      el.style.display = 'none';
    }
  }

  /* ── DATA COLLECTION ────────────────────────────────────────────── */

  function collectSearchData() {
    return {
      area:           val('hCity'),
      checkIn:        val('hIn'),
      checkOut:       val('hOut'),
      guests:         val('hGuests'),
      budgetMin:      val('hBudgetMin'),
      budgetMax:      val('hBudgetMax'),
      propertyType:   val('hPropType'),
      bedrooms:       val('hBedReq'),
      special:        val('hSpecial'),
      nights:         calculateNights(val('hIn'), val('hOut'))
    };
  }

  /* ── VALIDATION ─────────────────────────────────────────────────── */

  function validateSearch(data) {
    var fields = [
      { id: 'hCity',  val: data.area,        label: 'Area' },
      { id: 'hIn',    val: data.checkIn,      label: 'Check-in' },
      { id: 'hOut',   val: data.checkOut,     label: 'Check-out' },
      { id: 'hGuests', val: data.guests,      label: 'Guests' }
    ];
    var hasBudget = data.budgetMin || data.budgetMax;
    var ok = true;
    var firstBad = null;

    for (var i = 0; i < fields.length; i++) {
      var bad = !fields[i].val;
      setErr(fields[i].id, bad);
      if (bad && !firstBad) { firstBad = fields[i].id; ok = false; }
    }

    if (!hasBudget) {
      setErr('hBudgetMin', true);
      setErr('hBudgetMax', true);
      if (!firstBad) firstBad = 'hBudgetMin';
      ok = false;
    } else {
      setErr('hBudgetMin', false);
      setErr('hBudgetMax', false);
    }

    if (data.checkIn && data.checkOut && data.checkIn >= data.checkOut) {
      setErr('hOut', true);
      if (!firstBad) firstBad = 'hOut';
      ok = false;
    }

    if (data.nights === 0 && data.checkIn && data.checkOut) {
      setErr('hOut', true);
      if (!firstBad) firstBad = 'hOut';
      ok = false;
    }

    if (!ok && firstBad) {
      var el = document.getElementById(firstBad);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return ok;
  }

  /* ── BUILD WHATSAPP MESSAGE ─────────────────────────────────────── */

  function buildStayRequest(data) {
    var L = [];
    var SEP = '━━━━━━━━━━━━━━━━';

    L.push('🏠 KOR DA STAY REQUEST');
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('📍 Destination');
    L.push('Area / Sector: ' + (data.area || 'All Islamabad'));
    L.push('');

    L.push('📅 Check-in');
    L.push(formatDate(data.checkIn) || 'Not specified');
    L.push('');

    L.push('📅 Check-out');
    L.push(formatDate(data.checkOut) || 'Not specified');
    L.push('');

    L.push('🌙 Total Nights');
    L.push(data.nights > 0 ? data.nights + '' : 'Not calculated');
    L.push('');

    L.push('👥 Guests');
    L.push(data.guests || 'Not specified');
    L.push('');

    L.push('💰 Budget Per Night');
    if (data.budgetMin && data.budgetMax) {
      L.push('PKR ' + parseInt(data.budgetMin).toLocaleString('en-PK') + ' – ' + parseInt(data.budgetMax).toLocaleString('en-PK'));
    } else if (data.budgetMin) {
      L.push('PKR ' + parseInt(data.budgetMin).toLocaleString('en-PK') + ' minimum');
    } else if (data.budgetMax) {
      L.push('PKR ' + parseInt(data.budgetMax).toLocaleString('en-PK') + ' maximum');
    }
    L.push('');

    L.push('🏡 Preferred Property Type');
    L.push(data.propertyType || 'Any');
    L.push('');

    L.push('🛏 Bedrooms Required');
    L.push(data.bedrooms || 'Any');
    L.push('');

    L.push('⭐ Special Requirements');
    if (data.special) {
      var lines = data.special.split('\n');
      for (var i = 0; i < lines.length; i++) {
        L.push('• ' + lines[i]);
      }
    } else {
      L.push('• None specified');
    }
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('Please send available properties matching my requirements.');
    L.push('');
    L.push('Submitted via Kor Da Website');

    return L.join('\n');
  }

  /* ── SUBMIT (swap this for API later) ───────────────────────────── */

  function submitSearch(data) {
    var message = buildStayRequest(data);

    /* Future: replace this block with an API call
    fetch('/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }).then(...)
    */

    if (typeof toast === 'function') toast('Opening WhatsApp...', 'ok');

    var wa = (window.KORDA_CONFIG && window.KORDA_CONFIG.waNumber) ? window.KORDA_CONFIG.waNumber : '923155881733';
    window.open('https://wa.me/' + wa + '?text=' + encodeURIComponent(message), '_blank', 'noopener');
  }

  /* ── MAIN SEARCH ENTRY POINT ────────────────────────────────────── */

  window.doSearch = function() {
    var data = collectSearchData();
    if (!validateSearch(data)) {
      if (typeof toast === 'function') toast('Please fill all required fields', 'warn');
      return;
    }
    submitSearch(data);
  };

  /* ── CATEGORY FILTER (unchanged, for listing filter buttons) ────── */

  window.fCat = async function(btn) {
    var fps = document.querySelectorAll('.fp');
    for (var i = 0; i < fps.length; i++) {
      fps[i].classList.remove('on');
      fps[i].setAttribute('aria-pressed', 'false');
    }
    btn.classList.add('on');
    btn.setAttribute('aria-pressed', 'true');
    var cat = btn.dataset.cat || 'all';
    var results = await window.PropertyService.search({ category: cat });
    window.renderListings(results);
  };

  window.gFilter = async function(cat) {
    var btn = document.querySelector('.fp[data-cat="' + cat + '"]') || document.querySelector('.fp[data-cat="all"]');
    if (btn) window.fCat(btn);
    setTimeout(function() {
      var el = document.getElementById('listings');
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  };

  /* ── BOOT ───────────────────────────────────────────────────────── */

  window.addEventListener('DOMContentLoaded', function() {
    var hIn = document.getElementById('hIn');
    var hOut = document.getElementById('hOut');
    if (hIn) hIn.addEventListener('change', updateNightsDisplay);
    if (hOut) hOut.addEventListener('change', updateNightsDisplay);
  });

})();
