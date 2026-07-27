/**
 * KOR DA — FORM & WHATSAPP FLOW (forms.js)
 * Modular: collect → validate → build message → submit
 * Data collection separated from submission for future API swap.
 */
(function(){
  'use strict';

  /* ── AMENITY LIST ──────────────────────────────────────────────── */
  var AMENITY_OPTIONS = [
    'WiFi', 'Air Conditioning', 'Kitchen', 'Parking', 'TV',
    'Washing Machine', 'Geyser', 'UPS / Generator', 'Security',
    'Balcony', 'Gym', 'Elevator', 'Pool Access', 'Garden',
    'Iron / Steamer', 'Microwave', 'Refrigerator', 'Study Desk'
  ];

  /* ── HELPERS ────────────────────────────────────────────────────── */

  function getWaNumber() {
    return (window.KORDA_CONFIG && window.KORDA_CONFIG.waNumber) ? window.KORDA_CONFIG.waNumber : '923155881733';
  }

  function val(id) {
    var el = document.getElementById(id);
    return el ? (el.value || '').trim() : '';
  }

  function setErr(id, bad) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('err', bad);
  }

  /* ── GENERIC FORM VALIDATION ───────────────────────────────────── */

  window.fval = function(form) {
    var ok = true;
    var reqs = form.querySelectorAll('[required]');
    for (var i = 0; i < reqs.length; i++) {
      var f = reqs[i];
      var v = (f.value || '').trim();
      var bad = !v
        || (f.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))
        || (f.type === 'checkbox' && !f.checked);
      f.classList.toggle('err', bad);
      if (bad) ok = false;
    }
    return ok;
  };

  /* ── WHATSAPP ──────────────────────────────────────────────────── */

  window.openWA = function(text) {
    var url = 'https://wa.me/' + getWaNumber() + '?text=' + encodeURIComponent(text);
    window.open(url, '_blank', 'noopener');
  };

  window.showFormSuccess = function(form, message, waText) {
    if (typeof toast === 'function') toast(message || 'Submitted!', 'ok');
    form.style.opacity = '0.5';
    setTimeout(function() {
      form.style.opacity = '1';
      form.reset();
      if (waText) window.openWA(waText);
    }, 600);
  };

  /* ── PHOTO UPLOAD ──────────────────────────────────────────────── */

  var HOST_PHOTOS = [];
  var MAX_HOST_PHOTOS = 10;

  function compressHostImage(dataUrl, maxW, quality, cb) {
    var img = new Image();
    img.onload = function() {
      var w = img.width, h = img.height;
      if (w > maxW) { h = Math.round(h * maxW / w); w = maxW; }
      var c = document.createElement('canvas');
      c.width = w; c.height = h;
      c.getContext('2d').drawImage(img, 0, 0, w, h);
      cb(c.toDataURL('image/jpeg', quality));
    };
    img.src = dataUrl;
  }

  function renderHostPhotos() {
    var box = document.getElementById('pprev');
    if (!box) return;
    if (!HOST_PHOTOS.length) { box.innerHTML = ''; return; }
    box.innerHTML = HOST_PHOTOS.map(function(p, i) {
      return '<div class="pthumb">'
        + '<img src="' + p.dataUrl + '" alt="' + (p.name || 'photo') + '">'
        + '<div class="pthumb-rm" data-idx="' + i + '">&#10005;</div>'
        + '</div>';
    }).join('');
  }

  function handleHostFiles(files) {
    var remaining = MAX_HOST_PHOTOS - HOST_PHOTOS.length;
    if (remaining <= 0) { if (typeof toast === 'function') toast('Max 10 photos', 'warn'); return; }
    var toLoad = Math.min(files.length, remaining);
    var loaded = 0;
    for (var i = 0; i < toLoad; i++) {
      (function(file) {
        if (file.size > 10 * 1024 * 1024) {
          if (typeof toast === 'function') toast(file.name + ' too large (max 10MB)', 'warn');
          loaded++; return;
        }
        var reader = new FileReader();
        reader.onload = function(e) {
          compressHostImage(e.target.result, 1200, 0.8, function(compressed) {
            HOST_PHOTOS.push({ dataUrl: compressed, name: file.name });
            loaded++;
            if (loaded === toLoad) renderHostPhotos();
          });
        };
        reader.readAsDataURL(file);
      })(files[i]);
    }
  }

  function initHostPhotoUpload() {
    var drop = document.getElementById('pdrop');
    var inp = document.getElementById('pinp');
    if (!drop || !inp) return;

    drop.addEventListener('click', function(e) {
      if (e.target.classList.contains('pthumb-rm')) return;
      inp.click();
    });

    inp.addEventListener('change', function() {
      if (this.files.length) handleHostFiles(this.files);
      this.value = '';
    });

    drop.addEventListener('dragover', function(e) { e.preventDefault(); drop.classList.add('drag'); });
    drop.addEventListener('dragleave', function() { drop.classList.remove('drag'); });
    drop.addEventListener('drop', function(e) {
      e.preventDefault();
      drop.classList.remove('drag');
      if (e.dataTransfer.files.length) handleHostFiles(e.dataTransfer.files);
    });

    var prev = document.getElementById('pprev');
    if (prev) {
      prev.addEventListener('click', function(e) {
        var rm = e.target.closest('.pthumb-rm');
        if (rm) {
          var idx = parseInt(rm.getAttribute('data-idx'), 10);
          HOST_PHOTOS.splice(idx, 1);
          renderHostPhotos();
        }
      });
    }
  }

  /* ── AMENITY BUTTONS ───────────────────────────────────────────── */

  function initAmenityButtons() {
    var container = document.getElementById('amw');
    if (!container) return;
    container.innerHTML = AMENITY_OPTIONS.map(function(a) {
      return '<div class="am" data-am="' + a + '" onclick="this.classList.toggle(\'on\')">' + a + '</div>';
    }).join('');
  }

  /* ── HOST FORM: DATA COLLECTION ────────────────────────────────── */

  function collectHostFormData() {
    return {
      fullName:       val('hN'),
      whatsapp:       val('hPh'),
      cnic:           val('hCn'),
      email:          val('hEm'),
      address:        val('hAd'),
      area:           val('hAr'),
      propertyType:   val('hTy'),
      bedrooms:       val('hBd'),
      pricePerNight:  val('hPr'),
      maxGuests:      val('hMG'),
      category:       val('hCt'),
      description:    val('hDs'),
      amenities:      getSelectedAmenities(),
      photoCount:     HOST_PHOTOS.length,
      agreement:      !!document.getElementById('agr') && document.getElementById('agr').checked
    };
  }

  function getSelectedAmenities() {
    var tags = document.querySelectorAll('#amw .am.on');
    var list = [];
    for (var i = 0; i < tags.length; i++) {
      list.push(tags[i].getAttribute('data-am'));
    }
    return list;
  }

  /* ── HOST FORM: VALIDATION ─────────────────────────────────────── */

  function validateListingForm(data) {
    var fields = [
      { id: 'hN',  val: data.fullName,      label: 'Full Name' },
      { id: 'hPh', val: data.whatsapp,       label: 'WhatsApp Number' },
      { id: 'hCn', val: data.cnic,           label: 'CNIC Number' },
      { id: 'hAd', val: data.address,        label: 'Address' },
      { id: 'hAr', val: data.area,           label: 'Area / City' },
      { id: 'hTy', val: data.propertyType,   label: 'Property Type' },
      { id: 'hBd', val: data.bedrooms,       label: 'Bedrooms' },
      { id: 'hPr', val: data.pricePerNight,  label: 'Price per Night' }
    ];
    var ok = true;
    var firstBad = null;
    for (var i = 0; i < fields.length; i++) {
      var bad = !fields[i].val;
      setErr(fields[i].id, bad);
      if (bad && !firstBad) firstBad = fields[i].id;
    }
    if (!data.agreement) {
      var agr = document.getElementById('agr');
      if (agr) agr.style.outline = '2px solid var(--err)';
      if (!firstBad) firstBad = 'agr';
      ok = false;
    } else {
      var agrEl = document.getElementById('agr');
      if (agrEl) agrEl.style.outline = '';
    }
    if (!ok && firstBad) {
      var el = document.getElementById(firstBad);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return ok;
  }

  /* ── HOST FORM: BUILD WHATSAPP MESSAGE ─────────────────────────── */

  function buildWhatsAppMessage(data) {
    var L = [];
    var SEP = '━━━━━━━━━━━━━━━━';

    L.push('🏠 NEW PROPERTY LISTING APPLICATION');
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('👤 HOST DETAILS');
    L.push('• Full Name: ' + (data.fullName || '—'));
    L.push('• WhatsApp Number: ' + (data.whatsapp || '—'));
    L.push('• CNIC Number: ' + (data.cnic || '—'));
    L.push('• Email: ' + (data.email || '—'));
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('📍 PROPERTY DETAILS');
    L.push('• Full Address: ' + (data.address || '—'));
    L.push('• Area / City: ' + (data.area || '—'));
    L.push('• Property Type: ' + (data.propertyType || '—'));
    L.push('• Bedrooms: ' + (data.bedrooms || '—'));
    L.push('• Price per Night (PKR): ' + (data.pricePerNight || '—'));
    L.push('• Maximum Guests: ' + (data.maxGuests || '—'));
    L.push('• Best Category: ' + (data.category || 'General'));
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('📝 DESCRIPTION');
    L.push(data.description || '—');
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('🏡 AMENITIES');
    if (data.amenities.length) {
      for (var i = 0; i < data.amenities.length; i++) {
        L.push('• ' + data.amenities[i]);
      }
    } else {
      L.push('• None selected');
    }
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('📸 PHOTOS');
    L.push('Photos Selected: ' + data.photoCount);
    if (data.photoCount > 0) {
      L.push('');
      L.push('⚠️ IMPORTANT: Please attach the selected property photos before sending this WhatsApp message.');
    }
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('✅ HOST AGREEMENT');
    L.push('Agreement Accepted: ' + (data.agreement ? 'Yes' : 'No'));
    L.push('');
    L.push(SEP);
    L.push('');
    L.push('Submitted from Kor Da Listing Form');

    return L.join('\n');
  }

  /* ── HOST FORM: SUBMIT (swap this for API later) ───────────────── */

  function submitListing(data) {
    var message = buildWhatsAppMessage(data);

    /* Future: replace this block with an API call
    fetch('/api/host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }).then(...)

    For now, opens WhatsApp with the built message.
    */

    if (typeof toast === 'function') {
      if (data.photoCount > 0) {
        toast('Listing ready! Attach your ' + data.photoCount + ' photo(s) in WhatsApp before sending.', 'ok', 5000);
      } else {
        toast('Listing details ready. Opening WhatsApp...', 'ok');
      }
    }

    window.openWA(message);
  }

  /* ── HOST FORM: WIRE UP ────────────────────────────────────────── */

  function initHostForm() {
    var hform = document.getElementById('hform');
    if (!hform) return;

    hform.addEventListener('submit', function(e) {
      e.preventDefault();
      var data = collectHostFormData();
      if (!validateListingForm(data)) {
        if (typeof toast === 'function') toast('Please fill all required fields', 'warn');
        return;
      }
      submitListing(data);
      HOST_PHOTOS = [];
      renderHostPhotos();
      hform.reset();
      document.querySelectorAll('#amw .am.on').forEach(function(el) { el.classList.remove('on'); });
    });
  }

  /* ── WAITLIST FORM ─────────────────────────────────────────────── */

  function initWaitlistForm() {
    var wlf = document.getElementById('wlf');
    if (!wlf) return;
    wlf.addEventListener('submit', function(e) {
      e.preventDefault();
      var em = val('wle');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
        if (typeof toast === 'function') toast('Valid email required', 'warn');
        return;
      }
      window.showFormSuccess(wlf, 'Added to waitlist!', 'Hi Kor Da, please add me to the waitlist: ' + em);
    });
  }

  /* ── CONTACT FORM ──────────────────────────────────────────────── */

  function initContactForm() {
    var cf = document.getElementById('cf');
    if (!cf) return;
    cf.addEventListener('submit', function(e) {
      e.preventDefault();
      if (!window.fval(cf)) {
        if (typeof toast === 'function') toast('Please fill all required fields', 'warn');
        return;
      }
      var name = val('cN');
      var msg = val('cM');
      window.showFormSuccess(cf, 'Message sent!', 'Hi Kor Da, message from ' + name + ': ' + msg);
    });
  }

  /* ── BOOT ──────────────────────────────────────────────────────── */

  window.addEventListener('DOMContentLoaded', function() {
    initAmenityButtons();
    initHostPhotoUpload();
    initHostForm();
    initWaitlistForm();
    initContactForm();
  });

})();
