/**
 * KOR DA — FAVORITES JS (favorites.js)
 * LocalStorage bookmarking for saved properties
 */
(function(){
  'use strict';

  var favs = new Set(JSON.parse(localStorage.getItem('kd_f') || '[]'));

  window.togFav = function(btn){
    var card = btn.closest('.lcard');
    var id = card ? card.dataset.id : null;
    if(!id) return;
    if(favs.has(id)){
      favs.delete(id);
      btn.classList.remove('saved');
      btn.textContent = '♡';
      if(typeof toast === 'function') toast('Removed from saved stays');
    } else {
      favs.add(id);
      btn.classList.add('saved');
      btn.textContent = '♥';
      if(typeof toast === 'function') toast('Saved to favorites ♥');
    }
    localStorage.setItem('kd_f', JSON.stringify(Array.from(favs)));
  };
})();
