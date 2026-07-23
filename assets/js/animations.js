/**
 * KOR DA — ANIMATIONS JS (animations.js)
 * IntersectionObserver scroll reveal and animated stat counters
 */
(function(){
  'use strict';

  function fmt(n){ return parseInt(n).toLocaleString('en-PK'); }

  window.addEventListener('DOMContentLoaded', function(){
    /* Scroll reveal */
    window._rvObs = new IntersectionObserver(function(e){
      for(var i = 0; i < e.length; i++){
        if(e[i].isIntersecting) e[i].target.classList.add('vis');
      }
    }, { threshold: 0.08 });

    var rvEls = document.querySelectorAll('.rv');
    for(var i = 0; i < rvEls.length; i++){
      window._rvObs.observe(rvEls[i]);
    }

    /* Counter (stats bar) */
    var cntEl = document.getElementById('cnt20k');
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
  });
})();
