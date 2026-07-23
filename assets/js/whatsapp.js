/**
 * KOR DA — WHATSAPP & FORM HANDLING (whatsapp.js)
 *
 * All forms: validate → success animation → build WhatsApp message → open WA
 * Also compatible with Web3Forms (just add access_key to form and uncomment fetch)
 *
 * WhatsApp number: 0315-5881733 → wa.me/923155881733
 */
'use strict';

var WA_NUMBER = '923155881733';

/* ============================================================
   HERO SEARCH → WHATSAPP
   ============================================================ */
function doSearch(){
  var city = document.getElementById('hCity') ? document.getElementById('hCity').value : '';
  var ci   = document.getElementById('hIn')   ? document.getElementById('hIn').value   : '';
  var co   = document.getElementById('hOut')  ? document.getElementById('hOut').value  : '';

  if(ci && co && ci >= co){ toast('Check-out must be after check-in','warn'); return; }

  // Filter visible property cards
  if(city){
    var key = city.split(',')[0].toLowerCase();
    var cards = document.querySelectorAll('.lcard[data-cat]');
    for(var i = 0; i < cards.length; i++){
      var loc = (cards[i].querySelector('.lloc') ? cards[i].querySelector('.lloc').textContent : '').toLowerCase();
      cards[i].style.display = loc.indexOf(key) >= 0 ? '' : 'none';
    }
  }

  // Build WA message
  var msg = 'Hi Kor Da, I need a short stay in Islamabad.';
  if(city) msg = 'Hi Kor Da, I\'m looking for a stay in ' + city + '.';
  if(ci)   msg += ' Check-in: ' + ci + '.';
  if(co)   msg += ' Check-out: ' + co + '.';
  msg += ' Please share available properties and details.';

  var waUrl = 'https://wa.me/' + WA_NUMBER + '?text=' + encodeURIComponent(msg);

  toast(city ? 'Searching ' + city + '...' : 'Searching all Islamabad...', 'info');
  setTimeout(function(){
    var el = document.getElementById('listings');
    if(el) el.scrollIntoView({ behavior:'smooth', block:'start' });
    // Open WhatsApp after short delay
    setTimeout(function(){ window.open(waUrl, '_blank', 'noopener'); }, 800);
  }, 380);
}

/* ============================================================
   BOOK NOW (property card / property page)
   ============================================================ */
function bookNow(propertyName, price){
  var name = propertyName || 'your property';
  var msg  = 'Hi Kor Da, I\'m interested in ' + name + '. Please share availability and booking details.';
  if(price) msg += ' (Listed at PKR ' + price + '/night)';
  openWA(msg);
}

/* ============================================================
   FORM VALIDATION
   ============================================================ */
function fval(form){
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
}

/* ============================================================
   SUCCESS ANIMATION
   ============================================================ */
function showFormSuccess(form, successEl, message){
  form.style.display = 'none';
  if(!successEl) return;
  successEl.innerHTML =
    '<div class="fs-icon">✅</div>' +
    '<div class="fs-title">Message Sent!</div>' +
    '<p class="fs-sub">' + (message || 'Opening WhatsApp to complete your request...') + '</p>';
  successEl.classList.add('on');
  // After 4s, restore form
  setTimeout(function(){
    successEl.classList.remove('on');
    successEl.innerHTML = '';
    form.style.display = '';
    form.reset();
    // Reset amenities
    var amOns = document.querySelectorAll('.am.on');
    for(var i = 0; i < amOns.length; i++) amOns[i].classList.remove('on');
    // Reset photo previews
    var pp = document.getElementById('pprev');
    if(pp) pp.innerHTML = '';
  }, 4000);
}

/* ============================================================
   OPEN WHATSAPP
   ============================================================ */
function openWA(msg){
  window.open('https://wa.me/' + WA_NUMBER + '?text=' + encodeURIComponent(msg), '_blank', 'noopener');
}

/* ============================================================
   HOST FORM → VALIDATE → SUCCESS → WHATSAPP
   ============================================================ */
var hform = document.getElementById('hform');
var hformSuccess = document.getElementById('hform-success');
if(hform){
  hform.addEventListener('submit', function(e){
    e.preventDefault();
    if(!fval(hform)){ toast('Please fill all required fields','warn'); return; }

    var btn = hform.querySelector('[type=submit]');
    var orig = btn ? btn.innerHTML : '';
    if(btn){ btn.innerHTML = 'Processing...'; btn.disabled = true; }

    // Collect amenities
    var ams = document.querySelectorAll('.am.on');
    var amenities = [];
    for(var i = 0; i < ams.length; i++) amenities.push(ams[i].dataset.a);

    // Collect form values
    var name     = document.getElementById('hN')  ? document.getElementById('hN').value.trim()  : '';
    var phone    = document.getElementById('hPh') ? document.getElementById('hPh').value.trim() : '';
    var cnic     = document.getElementById('hCn') ? document.getElementById('hCn').value.trim() : '';
    var email    = document.getElementById('hEm') ? document.getElementById('hEm').value.trim() : '';
    var address  = document.getElementById('hAd') ? document.getElementById('hAd').value.trim() : '';
    var city     = document.getElementById('hAr') ? document.getElementById('hAr').value.trim() : '';
    var propType = document.getElementById('hTy') ? document.getElementById('hTy').value.trim() : '';
    var beds     = document.getElementById('hBd') ? document.getElementById('hBd').value.trim() : '';
    var price    = document.getElementById('hPr') ? document.getElementById('hPr').value.trim() : '';
    var maxGuests= document.getElementById('hMG') ? document.getElementById('hMG').value.trim() : '';
    var category = document.getElementById('hCt') ? document.getElementById('hCt').value.trim() : '';
    var desc     = document.getElementById('hDs') ? document.getElementById('hDs').value.trim() : '';

    // Build WhatsApp message
    var msg =
      '🏠 *NEW PROPERTY LISTING REQUEST*\n\n' +
      '*Host Details:*\n' +
      '• Name: ' + name + '\n' +
      '• WhatsApp: ' + phone + '\n' +
      '• CNIC: ' + cnic + '\n' +
      (email ? '• Email: ' + email + '\n' : '') +
      '\n*Property Details:*\n' +
      '• Address: ' + address + '\n' +
      '• Area/City: ' + city + '\n' +
      '• Type: ' + propType + '\n' +
      '• Bedrooms: ' + beds + '\n' +
      '• Price/Night: PKR ' + price + '\n' +
      '• Max Guests: ' + maxGuests + '\n' +
      (category ? '• Category: ' + category + '\n' : '') +
      (amenities.length ? '• Amenities: ' + amenities.join(', ') + '\n' : '') +
      (desc ? '\n*Description:*\n' + desc + '\n' : '') +
      '\n_Sent from Kor Da website_';

    /* --- Web3Forms integration (activate when ready) ---
    fetch('https://api.web3forms.com/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_key: 'YOUR_WEB3FORMS_KEY',
        subject: 'New Property Listing: ' + name,
        name: name, email: email, phone: phone,
        address: address, city: city, type: propType,
        price: price, amenities: amenities.join(', '),
        description: desc
      })
    }).catch(function(){}); // Silent fail — WA is primary
    */

    setTimeout(function(){
      if(btn){ btn.innerHTML = orig; btn.disabled = false; }
      showFormSuccess(hform, hformSuccess, 'Opening WhatsApp to complete your application. We\'ll verify your CNIC within 24 hours.');
      setTimeout(function(){ openWA(msg); }, 600);
    }, 800);
  });
}

/* ============================================================
   WAITLIST FORM → VALIDATE → SUCCESS → WHATSAPP
   ============================================================ */
var wlf = document.getElementById('wlf');
var wlfSuccess = document.getElementById('wlf-success');
if(wlf){
  wlf.addEventListener('submit', function(e){
    e.preventDefault();
    var em = document.getElementById('wle') ? document.getElementById('wle').value.trim() : '';
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)){ toast('Valid email required','warn'); return; }

    var btn = wlf.querySelector('[type=submit]');
    var orig = btn ? btn.innerHTML : '';
    if(btn){ btn.innerHTML = 'Joining...'; btn.disabled = true; }

    var msg = '📩 *WAITLIST SIGNUP*\n\nEmail: ' + em + '\n\nPlease add me to the Kor Da waitlist for early access and 10% off my first booking.\n\n_Sent from korda.pk_';

    /* --- Web3Forms integration ---
    fetch('https://api.web3forms.com/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_key: 'YOUR_KEY', subject: 'Waitlist Signup', email: em })
    }).catch(function(){});
    */

    setTimeout(function(){
      if(btn){ btn.innerHTML = orig; btn.disabled = false; }
      showFormSuccess(wlf, wlfSuccess, 'You\'re on the list! We\'ll WhatsApp you at launch with your 10% discount code.');
      toast("You're on the list! 🎉",'ok');
    }, 700);
  });
}

/* ============================================================
   CONTACT FORM → VALIDATE → SUCCESS → WHATSAPP
   ============================================================ */
var cf = document.getElementById('cf');
var cfSuccess = document.getElementById('cf-success');
if(cf){
  cf.addEventListener('submit', function(e){
    e.preventDefault();
    if(!fval(cf)){ toast('Please fill all required fields','warn'); return; }

    var btn = cf.querySelector('[type=submit]');
    var orig = btn ? btn.innerHTML : '';
    if(btn){ btn.innerHTML = 'Sending...'; btn.disabled = true; }

    var name    = document.getElementById('cN') ? document.getElementById('cN').value.trim() : '';
    var email   = document.getElementById('cE') ? document.getElementById('cE').value.trim() : '';
    var subject = document.getElementById('cS') ? document.getElementById('cS').value.trim() : '';
    var message = document.getElementById('cM') ? document.getElementById('cM').value.trim() : '';

    var waMsg =
      '📧 *CONTACT MESSAGE*\n\n' +
      '• Name: ' + name + '\n' +
      '• Email: ' + email + '\n' +
      (subject ? '• Subject: ' + subject + '\n' : '') +
      '\n*Message:*\n' + message +
      '\n\n_Sent from korda.pk_';

    /* --- Web3Forms integration ---
    fetch('https://api.web3forms.com/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_key: 'YOUR_KEY', subject: subject || 'Contact from ' + name, name: name, email: email, message: message })
    }).catch(function(){});
    */

    setTimeout(function(){
      if(btn){ btn.innerHTML = orig; btn.disabled = false; }
      showFormSuccess(cf, cfSuccess, 'Your message has been received. We\'ll reply within 2 hours!');
      setTimeout(function(){ openWA(waMsg); }, 600);
    }, 700);
  });
}

/* ============================================================
   SEARCH → WHATSAPP (hero quick search)
   ============================================================ */
// doSearch() defined above — also opens WA after filtering
