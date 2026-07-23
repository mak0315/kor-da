/**
 * KOR DA — INSTANT MULTI-CRITERIA SEARCH (search.js)
 * High-performance client-side property filter using PropertyService
 */
(function(){
  'use strict';

  window.doSearch = async function(){
    var city  = document.getElementById('hCity')  ? document.getElementById('hCity').value  : '';
    var ci    = document.getElementById('hIn')    ? document.getElementById('hIn').value    : '';
    var co    = document.getElementById('hOut')   ? document.getElementById('hOut').value   : '';
    var guests= document.getElementById('hGuests')? document.getElementById('hGuests').value: '';
    var type  = document.getElementById('hType')  ? document.getElementById('hType').value  : '';

    if(ci && co && ci >= co){ 
      if (typeof toast === 'function') toast('Check-out must be after check-in', 'warn'); 
      return; 
    }

    var filters = {};

    if (city) filters.keyword = city.split(',')[0].trim();
    if (guests) filters.maxGuests = parseInt(guests, 10);
    if (type && type !== 'all') filters.type = type;

    var results = await window.PropertyService.search(filters);
    window.renderListings(results);

    if (typeof toast === 'function') {
      toast(city ? 'Searching ' + city + '...' : 'Searching all Islamabad...', 'info');
    }

    setTimeout(function(){
      var el = document.getElementById('listings');
      if(el) el.scrollIntoView({ behavior:'smooth', block:'start' });
    }, 300);
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
