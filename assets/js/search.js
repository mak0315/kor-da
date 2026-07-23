/**
 * KOR DA — INSTANT MULTI-CRITERIA SEARCH (search.js)
 * High-performance client-side property filter using PropertyService
 */
(function(){
  'use strict';

  window.doSearch = function(){
    var city  = document.getElementById('hCity')  ? document.getElementById('hCity').value  : '';
    var ci    = document.getElementById('hIn')    ? document.getElementById('hIn').value    : '';
    var co    = document.getElementById('hOut')   ? document.getElementById('hOut').value   : '';
    var guests= document.getElementById('hGuests')? document.getElementById('hGuests').value: '';

    if(ci && co && ci >= co){
      if (typeof toast === 'function') toast('Check-out must be after check-in', 'warn');
      return;
    }

    var msg = 'Hi Kor Da, I need a short stay';
    if(city) msg += ' in ' + city;
    msg += '.';

    if(ci) msg += ' Check-in: ' + ci + '.';
    if(co) msg += ' Check-out: ' + co + '.';
    if(guests) msg += ' Guests: ' + guests + '.';

    msg += ' Please share available properties and details.';

    if(typeof openWA === 'function'){
      openWA(msg);
    } else {
      var wa = (window.KORDA_CONFIG && window.KORDA_CONFIG.waNumber) ? window.KORDA_CONFIG.waNumber : '923155881733';
      window.open('https://wa.me/' + wa + '?text=' + encodeURIComponent(msg), '_blank', 'noopener');
    }
  };

  window.fCat = async function(btn){
    var fps = document.querySelectorAll('.fp');
    for(var i = 0; i < fps.length; i++){
      fps[i].classList.remove('on');
      fps[i].setAttribute('aria-pressed','false');
    }
    btn.classList.add('on');
    btn.setAttribute('aria-pressed','true');

    var cat = btn.dataset.cat || 'all';
    var results = await window.PropertyService.search({ category: cat });
    window.renderListings(results);
  };

  window.gFilter = async function(cat){
    var btn = document.querySelector('.fp[data-cat="'+cat+'"]') || document.querySelector('.fp[data-cat="all"]');
    if(btn) window.fCat(btn);
    setTimeout(function(){
      var el = document.getElementById('listings');
      if(el) el.scrollIntoView({ behavior:'smooth', block:'start' });
    }, 100);
  };
})();
