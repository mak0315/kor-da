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

  window.addEventListener('DOMContentLoaded', function(){
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
