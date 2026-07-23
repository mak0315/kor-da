/**
 * KOR DA — HERO SLIDESHOW JS (hero.js)
 * Auto-advancing touch-enabled hero background slider
 */
(function(){
  'use strict';
  window.addEventListener('DOMContentLoaded', function(){
    var sl = document.querySelectorAll('.hs'),
        dt = document.querySelectorAll('.hd');
    var c = 0, t, n = sl.length;
    if(!n) return;

    function go(i){
      if(sl[c]) sl[c].classList.remove('on');
      if(dt[c]) dt[c].classList.remove('on');
      c = (i + n) % n;
      if(sl[c]) sl[c].classList.add('on');
      if(dt[c]) dt[c].classList.add('on');
    }

    function st(){
      t = setInterval(function(){ go(c + 1); }, 4600);
    }

    window.hsg = function(i){
      clearInterval(t);
      go(i);
      st();
    };

    var sx = 0;
    var hero = document.getElementById('hero');
    if(hero){
      hero.addEventListener('touchstart', function(e){
        sx = e.touches[0].clientX;
      }, { passive: true });

      hero.addEventListener('touchend', function(e){
        var dx = e.changedTouches[0].clientX - sx;
        if(Math.abs(dx) > 48){
          clearInterval(t);
          go(dx < 0 ? c + 1 : c - 1);
          st();
        }
      });
    }

    st();
  });
})();
