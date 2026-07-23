/**
 * KOR DA — CORE APP LOGIC (app.js)
 * Nav, slideshow, scroll reveal, counter, FAQ, calculator,
 * favorites, chat widget, lazy loading
 */
'use strict';

/* Utilities */
var $ = function(id){ return document.getElementById(id); };
var $$ = function(s){ return document.querySelectorAll(s); };
function fmt(n){ return parseInt(n).toLocaleString('en-PK'); }

function toast(msg, type, dur){
  type = type || 'ok'; dur = dur || 3400;
  var el = $('toast');
  var icons = { ok:'✓', warn:'⚠', err:'✗', info:'ℹ' };
  el.innerHTML = '<span>' + (icons[type] || '✓') + '</span> ' + msg;
  el.className = 'on ' + type;
  clearTimeout(el._t);
  el._t = setTimeout(function(){ el.classList.remove('on'); }, dur);
}

/* Navbar */
var nav = document.querySelector('#nav');
window.addEventListener('scroll', function(){
  nav.classList.toggle('sc', window.scrollY > 60);
}, { passive: true });

var nhbg = $('nhbg'), ndr = $('ndr'), novl = $('novl');
function openD(){
  nhbg.classList.add('open'); ndr.classList.add('open'); novl.classList.add('on');
  nhbg.setAttribute('aria-expanded','true'); document.body.style.overflow = 'hidden';
}
function closeD(){
  nhbg.classList.remove('open'); ndr.classList.remove('open'); novl.classList.remove('on');
  nhbg.setAttribute('aria-expanded','false'); document.body.style.overflow = '';
}
if(nhbg) nhbg.addEventListener('click', function(){ ndr.classList.contains('open') ? closeD() : openD(); });
if($('ndx')) $('ndx').addEventListener('click', closeD);
if(novl) novl.addEventListener('click', closeD);
var ndls = $$('.ndl');
for(var i = 0; i < ndls.length; i++){ ndls[i].addEventListener('click', closeD); }

/* Hero Slideshow */
(function(){
  var sl = $$('.hs'), dt = $$('.hd');
  var c = 0, t, n = sl.length;
  if(!n) return;
  function go(i){
    sl[c].classList.remove('on');
    if(dt[c]) dt[c].classList.remove('on');
    c = (i + n) % n;
    sl[c].classList.add('on');
    if(dt[c]) dt[c].classList.add('on');
  }
  function st(){ t = setInterval(function(){ go(c + 1); }, 4600); }
  window.hsg = function(i){ clearInterval(t); go(i); st(); };
  var sx = 0;
  var hero = $('hero');
  if(hero){
    hero.addEventListener('touchstart', function(e){ sx = e.touches[0].clientX; }, { passive: true });
    hero.addEventListener('touchend', function(e){
      var dx = e.changedTouches[0].clientX - sx;
      if(Math.abs(dx) > 48){ clearInterval(t); go(dx < 0 ? c + 1 : c - 1); st(); }
    });
  }
  st();
})();

/* Scroll Reveal */
var rvObs = new IntersectionObserver(function(e){
  for(var i = 0; i < e.length; i++){
    if(e[i].isIntersecting) e[i].target.classList.add('vis');
  }
}, { threshold: 0.08 });
var rvEls = $$('.rv');
for(var i = 0; i < rvEls.length; i++){ rvObs.observe(rvEls[i]); }

/* Counter */
var cntEl = $('cnt20k');
if(cntEl){
  var cntObs = new IntersectionObserver(function(e){
    if(e[0].isIntersecting && !cntEl._c){
      cntEl._c = 1;
      var tg = 20000, dur = 1800, start = null;
      function step(ts){
        if(!start) start = ts;
        var p = Math.min((ts - start) / dur, 1);
        var ez = 1 - Math.pow(1 - p, 3);
        cntEl.textContent = fmt(Math.round(ez * tg)) + (p >= 1 ? '+' : '');
        if(p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    }
  }, { threshold: 0.5 });
  cntObs.observe(cntEl);
}

/* Listing filtering routes to search.js (window.fCat / window.gFilter) */
function fCat(btn){ if (window.fCat) window.fCat(btn); }
function gFilter(cat){ if (window.gFilter) window.gFilter(cat); }

/* Area Filter */
function aArea(btn, area){
  if(btn){
    var atags = $$('.atag');
    for(var i = 0; i < atags.length; i++) atags[i].classList.remove('on');
    btn.classList.add('on');
  }
  if(area && window.PropertyService){
    var hc = $('hCity');
    if(hc){
      for(var i = 0; i < hc.options.length; i++){
        if(hc.options[i].value && hc.options[i].value.toLowerCase().indexOf(area.toLowerCase()) >= 0){
          hc.value = hc.options[i].value; break;
        }
      }
    }
    window.PropertyService.search({ area: area }).then(function(results){
      if (window.renderListings) window.renderListings(results);
    });
  }
  var el = $('listings'); if(el) el.scrollIntoView({ behavior:'smooth', block:'start' });
}

/* Earnings Calculator */
function uc(){
  var r = parseInt($('cr') ? $('cr').value : 5000);
  var n = parseInt($('cn') ? $('cn').value : 15);
  var g = r * n, c = Math.round(g * .09), net = g - c;
  if($('crv')) $('crv').textContent = 'PKR ' + fmt(r);
  if($('cnv')) $('cnv').textContent = n + ' nights';
  if($('cres')) $('cres').textContent = 'PKR ' + fmt(net);
  if($('csub')) $('csub').textContent = n + ' x PKR ' + fmt(r) + ' = PKR ' + fmt(g) + ' gross';
  if($('cg')) $('cg').textContent = 'PKR ' + fmt(g);
  if($('cc')) $('cc').textContent = '-PKR ' + fmt(c);
  if($('cn2')) $('cn2').textContent = 'PKR ' + fmt(net);
  var re = $('cr'), ne = $('cn');
  if(re) re.style.setProperty('--rp', (((r - 1000) / (30000 - 1000)) * 100).toFixed(1) + '%');
  if(ne) ne.style.setProperty('--rp', (((n - 1) / 29) * 100).toFixed(1) + '%');
}
window.addEventListener('load', uc);

/* FAQ Accordion */
function tfaq(btn){
  var item = btn.closest('[data-faq]');
  var was = item.classList.contains('on');
  var items = $$('[data-faq].on');
  for(var i = 0; i < items.length; i++) items[i].classList.remove('on');
  if(!was) item.classList.add('on');
}

/* Favorites (localStorage) */
var favs = new Set(JSON.parse(localStorage.getItem('kd_f') || '[]'));
function togFav(btn){
  var id = btn.closest('.lcard') ? btn.closest('.lcard').dataset.id : null;
  if(!id) return;
  if(favs.has(id)){
    favs.delete(id); btn.classList.remove('saved'); btn.textContent = '♡'; toast('Removed');
  } else {
    favs.add(id); btn.classList.add('saved'); btn.textContent = '♥'; toast('Saved ♥');
  }
  localStorage.setItem('kd_f', JSON.stringify(Array.from(favs)));
}

/* Amenities Picker */
var AMEN = ['WiFi','AC','Kitchen','Parking','UPS/Generator','Geyser','TV',
            'Washing Machine','Balcony','Garden','BBQ','Fireplace','Elevator','Swimming Pool'];
var amw = $('amw');
if(amw){
  AMEN.forEach(function(a){
    var d = document.createElement('div'); d.className = 'am'; d.textContent = a; d.dataset.a = a;
    d.addEventListener('click', function(){ d.classList.toggle('on'); });
    amw.appendChild(d);
  });
}

/* Photo Upload */
var uf = [];
var pd = $('pdrop'), pi = $('pinp'), pp = $('pprev');
if(pd){
  pd.addEventListener('click', function(){ if(pi) pi.click(); });
  pd.addEventListener('keypress', function(e){ if((e.key === 'Enter' || e.key === ' ') && pi) pi.click(); });
  pd.addEventListener('dragover', function(e){ e.preventDefault(); pd.classList.add('drag'); });
  pd.addEventListener('dragleave', function(){ pd.classList.remove('drag'); });
  pd.addEventListener('drop', function(e){
    e.preventDefault(); pd.classList.remove('drag');
    hf(Array.from(e.dataTransfer.files));
  });
}
if(pi) pi.addEventListener('change', function(e){ hf(Array.from(e.target.files)); });
function hf(files){
  files.filter(function(f){ return f.type.indexOf('image/') === 0; }).forEach(function(f){
    if(f.size > 10 * 1024 * 1024){ toast(f.name + ' too large (max 10MB)','warn'); return; }
    uf.push(f);
    var r = new FileReader();
    r.onload = function(ev){
      var d = document.createElement('div'); d.className = 'pthumb';
      var im = new Image(); im.src = ev.target.result; im.alt = 'Photo';
      im.setAttribute('loading','lazy');
      var rm = document.createElement('button');
      rm.className = 'pthumb-rm'; rm.textContent = '×'; rm.setAttribute('aria-label','Remove');
      rm.addEventListener('click', function(){ d.remove(); });
      d.appendChild(im); d.appendChild(rm);
      if(pp) pp.appendChild(d);
    };
    r.readAsDataURL(f);
  });
}

/* Date Defaults */
(function(){
  var today = new Date();
  function fd(d){ return d.toISOString().split('T')[0]; }
  var t1 = new Date(today); t1.setDate(t1.getDate() + 1);
  var t3 = new Date(today); t3.setDate(t3.getDate() + 3);
  var inp = $('hIn'), out = $('hOut');
  if(inp){ inp.min = fd(today); inp.value = fd(t1); }
  if(out){ out.min = fd(t1); out.value = fd(t3); }
})();

/* Chat Widget */
var cOpen = false;
var cpanel = $('cpanel'), cfab = $('cfab'), cbadge = $('cbadge');
setTimeout(function(){ if(cbadge) cbadge.style.opacity = '0'; }, 3200);

function tChat(){
  cOpen = !cOpen;
  if(cpanel) cpanel.classList.toggle('open', cOpen);
  if(cfab) cfab.setAttribute('aria-expanded', String(cOpen));
  if(cOpen && cbadge) cbadge.style.opacity = '0';
}

function sCTab(btn){
  var tabs = $$('.ctab'); for(var i = 0; i < tabs.length; i++) tabs[i].classList.remove('on');
  btn.classList.add('on');
  var panes = $$('.cpane'); for(var i = 0; i < panes.length; i++) panes[i].classList.remove('on');
  var pane = $('pt-' + btn.dataset.tab); if(pane) pane.classList.add('on');
}

var AR = [
  {k:['easypais','jazzcash','pay','payment'],r:'We accept EasyPaisa, JazzCash, debit/credit card, and bank transfer — all in PKR. Call/WhatsApp: 0315-5881733'},
  {k:['book','booking','reserve','available'],r:'WhatsApp us at 0315-5881733 with the property name and dates. We respond within 2 hours!'},
  {k:['cnic','nadra','verify'],r:'Every host is verified via NADRA Verisys before listing. Only CNIC-verified Pakistanis can host on Kor Da.'},
  {k:['hello','hi','salam','aoa','assalam'],r:'Wa Alaikum Assalam! 👋 Welcome to Kor Da Islamabad. Looking for a stay or want to list your property?'},
  {k:['commission','fee','percent'],r:'Kor Da charges hosts only 9% on completed bookings — lowest in Pakistan. You keep 91%.'},
  {k:['f-7','f-8','dha','bahria','g-8','islamabad','pims','nust'],r:'We cover all of Islamabad: F-6 to F-11, G-6 to G-15, DHA, Bahria Town, Blue Area, Bani Gala and all sectors.'},
  {k:['safe','trust','secure','escrow'],r:'CNIC-verified hosts. 24-hour dispute protection. WhatsApp: 0315-5881733 for any issue.'},
  {k:['cancel','refund'],r:'Contact us within 24 hours of check-in via WhatsApp: 0315-5881733. We respond same day.'}
];

function sChat(){
  var inp = $('cin'), ml = $('cml');
  var text = inp ? inp.value.trim() : '';
  if(!text) return;
  addMsg(ml, text, 'out'); inp.value = '';
  var low = text.toLowerCase();
  var match = null;
  for(var i = 0; i < AR.length; i++){
    for(var j = 0; j < AR[i].k.length; j++){
      if(low.indexOf(AR[i].k[j]) >= 0){ match = AR[i]; break; }
    }
    if(match) break;
  }
  var reply = match ? match.r : 'For fastest help WhatsApp us at 0315-5881733 — we reply in minutes!';
  setTimeout(function(){ addMsg(ml, reply, 'in'); }, 900);
}

function addMsg(c, t, type){
  var d = document.createElement('div'); d.className = 'cmsg ' + type; d.textContent = t;
  c.appendChild(d); c.scrollTop = c.scrollHeight;
}

document.addEventListener('click', function(e){
  if(cOpen && cpanel && cfab && !cpanel.contains(e.target) && !cfab.contains(e.target)){
    cOpen = false; cpanel.classList.remove('open'); cfab.setAttribute('aria-expanded','false');
  }
});

var cinEl = $('cin');
if(cinEl) cinEl.addEventListener('keypress', function(e){ if(e.key === 'Enter') sChat(); });

/* Lazy Image Loading */
if('IntersectionObserver' in window){
  var imgObs = new IntersectionObserver(function(e){
    e.forEach(function(entry){
      if(entry.isIntersecting){
        var img = entry.target;
        if(img.dataset.src){ img.src = img.dataset.src; delete img.dataset.src; }
        imgObs.unobserve(img);
      }
    });
  }, { rootMargin:'200px 0px' });
  $$('img[loading="lazy"]').forEach(function(img){ imgObs.observe(img); });
}

/* Listing rendering is in cms.js (renderListings via PropertyCard) */

console.log('%cKor Da — Static MVP v2.0','background:#1C4D40;color:#fff;padding:8px 16px;border-radius:6px;font-weight:700');
console.log('%c0315-5881733 | kordapakistan@gmail.com | @korda.pk','color:#1C4D40;font-size:11px');
