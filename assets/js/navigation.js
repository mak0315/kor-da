/**
 * KOR DA — NAVIGATION JS (navigation.js)
 * Sticky header scroll behavior & mobile drawer controls
 */
(function(){
  'use strict';
  window.addEventListener('DOMContentLoaded', function(){
    var nav = document.querySelector('#nav') || document.querySelector('header nav');
    if (nav) {
      window.addEventListener('scroll', function(){
        nav.classList.toggle('sc', window.scrollY > 60);
      }, { passive: true });
    }

    var nhbg = document.getElementById('nhbg'),
        ndr  = document.getElementById('ndr'),
        novl = document.getElementById('novl'),
        ndx  = document.getElementById('ndx');

    function openD(){
      if(nhbg) nhbg.classList.add('open');
      if(ndr) ndr.classList.add('open');
      if(novl) novl.classList.add('on');
      if(nhbg) nhbg.setAttribute('aria-expanded','true');
      document.body.style.overflow = 'hidden';
    }

    function closeD(){
      if(nhbg) nhbg.classList.remove('open');
      if(ndr) ndr.classList.remove('open');
      if(novl) novl.classList.remove('on');
      if(nhbg) nhbg.setAttribute('aria-expanded','false');
      document.body.style.overflow = '';
    }

    if(nhbg) {
      nhbg.addEventListener('click', function(){
        ndr && ndr.classList.contains('open') ? closeD() : openD();
      });
    }
    if(ndx) ndx.addEventListener('click', closeD);
    if(novl) novl.addEventListener('click', closeD);

    var ndls = document.querySelectorAll('.ndl');
    for(var i = 0; i < ndls.length; i++){
      ndls[i].addEventListener('click', closeD);
    }
  });
})();
