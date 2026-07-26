/**
 * KOR DA — FORM & WHATSAPP FLOW (forms.js)
 * Form validation → Animated success modal → Open WhatsApp (KORDA_CONFIG.waNumber)
 * Compatible with Web3Forms (standard <form> fields)
 */
(function(){
  'use strict';

  function getWaNumber() {
    return (window.KORDA_CONFIG && window.KORDA_CONFIG.waNumber) ? window.KORDA_CONFIG.waNumber : '923155881733';
  }

  /* Form Validation */
  window.fval = function(form){
    var ok = true;
    var reqs = form.querySelectorAll('[required]');
    for(var i = 0; i < reqs.length; i++){
      var f = reqs[i];
      var v = (f.value || '').trim();
      var bad = !v 
        || (f.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))
        || (f.type === 'checkbox' && !f.checked);
      f.classList.toggle('err', bad);
      if(bad) ok = false;
    }
    return ok;
  };

  /* Open WhatsApp with prefilled message */
  window.openWA = function(text){
    var url = 'https://wa.me/' + getWaNumber() + '?text=' + encodeURIComponent(text);
    window.open(url, '_blank', 'noopener');
  };

  /* Form success modal and delayed WhatsApp launch */
  window.showFormSuccess = function(form, message, waText){
    if (typeof toast === 'function') {
      toast('Form submitted! Opening WhatsApp...', 'ok');
    }
    
    // Animate form container
    form.style.opacity = '0.5';
    setTimeout(function(){
      form.style.opacity = '1';
      form.reset();
      if (waText) {
        window.openWA(waText);
      }
    }, 600);
  };

  /* ── Photo upload for host form ── */
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

  window.addEventListener('DOMContentLoaded', function(){
    initHostPhotoUpload();

    // Host Form
    var hform = document.getElementById('hform');
    if(hform){
      hform.addEventListener('submit', function(e){
        e.preventDefault();
        if(!window.fval(hform)){
          if (typeof toast === 'function') toast('Please fill all required fields', 'warn');
          return;
        }
        var name = document.getElementById('hN') ? document.getElementById('hN').value : '';
        var city = document.getElementById('hAr') ? document.getElementById('hAr').value : 'Islamabad';
        var type = document.getElementById('hTy') ? document.getElementById('hTy').value : 'Property';
        var beds = document.getElementById('hBd') ? document.getElementById('hBd').value : '';
        
        var waMsg = 'Hi Kor Da, I want to list my property in ' + city + '. Details: ' + name + ' (' + beds + ' ' + type + ').';
        if (HOST_PHOTOS.length) waMsg += ' I have ' + HOST_PHOTOS.length + ' photo' + (HOST_PHOTOS.length > 1 ? 's' : '') + ' to share.';
        HOST_PHOTOS = [];
        renderHostPhotos();
        window.showFormSuccess(hform, 'Host application received!', waMsg);
      });
    }

    // Waitlist Form
    var wlf = document.getElementById('wlf');
    if(wlf){
      wlf.addEventListener('submit', function(e){
        e.preventDefault();
        var em = document.getElementById('wle') ? document.getElementById('wle').value : '';
        if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)){
          if (typeof toast === 'function') toast('Valid email required', 'warn');
          return;
        }
        var waMsg = 'Hi Kor Da, please add me to the waitlist: ' + em;
        window.showFormSuccess(wlf, 'Added to waitlist!', waMsg);
      });
    }

    // Contact Form
    var cf = document.getElementById('cf');
    if(cf){
      cf.addEventListener('submit', function(e){
        e.preventDefault();
        if(!window.fval(cf)){
          if (typeof toast === 'function') toast('Please fill all required fields', 'warn');
          return;
        }
        var name = document.getElementById('cN') ? document.getElementById('cN').value : '';
        var msg = document.getElementById('cM') ? document.getElementById('cM').value : '';
        var waMsg = 'Hi Kor Da, message from ' + name + ': ' + msg;
        window.showFormSuccess(cf, 'Message sent!', waMsg);
      });
    }
  });
})();
