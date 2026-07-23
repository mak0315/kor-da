/**
 * KOR DA — FAQ ACCORDION JS (faq.js)
 */
(function(){
  'use strict';

  window.tfaq = function(btn){
    var item = btn.closest('[data-faq]');
    if (!item) return;
    var was = item.classList.contains('on');
    var items = document.querySelectorAll('[data-faq].on');
    for(var i = 0; i < items.length; i++){
      items[i].classList.remove('on');
    }
    if(!was) item.classList.add('on');
  };
})();
