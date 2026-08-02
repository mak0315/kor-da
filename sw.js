/**
 * KOR DA — SERVICE WORKER (sw.js)
 * Versioned cache: precache core shell, network-first for navigation,
 * stale-while-revalidate for same-origin assets. Admin/CMS paths are bypassed.
 */
'use strict';

var VERSION = 'korda-v1';

var CORE = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/assets/css/main.css',
  '/assets/images/kor-da-logo.jpg',
  '/images/favicon-192.png',
  '/images/favicon-512.png'
];

function isAdmin(url){
  return url.pathname.indexOf('/admin') === 0 || url.pathname.indexOf('/_admin_korda_secret') === 0;
}

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(VERSION).then(function(c){ return c.addAll(CORE); }).then(function(){
      return self.skipWaiting();
    })
  );
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(
        keys.filter(function(k){ return k !== VERSION; }).map(function(k){ return caches.delete(k); })
      );
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e){
  var req = e.request;
  var url = new URL(req.url);

  if(req.method !== 'GET' || url.origin !== self.location.origin || isAdmin(url)) return;

  /* Navigations: network first, fall back to cached homepage when offline. */
  if(req.mode === 'navigate'){
    e.respondWith(
      fetch(req).then(function(res){
        var copy = res.clone();
        caches.open(VERSION).then(function(c){ c.put(req, copy); });
        return res;
      }).catch(function(){
        return caches.match('/');
      })
    );
    return;
  }

  /* Static assets: cache first, refresh in background. */
  e.respondWith(
    caches.match(req).then(function(cached){
      var live = fetch(req).then(function(res){
        if(res && res.status === 200 && res.type === 'basic'){
          var copy = res.clone();
          caches.open(VERSION).then(function(c){ c.put(req, copy); });
        }
        return res;
      }).catch(function(){ return cached; });
      return cached || live;
    })
  );
});
