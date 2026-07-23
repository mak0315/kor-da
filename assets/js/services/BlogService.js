/**
 * KOR DA — BLOG SERVICE (BlogService.js)
 *
 * Abstraction layer for blog posts.
 * Reads from content/compiled/blog.json (built by scripts/build-content.js).
 * Migration Boundary: To switch to Supabase/REST, update only this file.
 */
(function(){
  'use strict';

  var cache = null;

  var DEFAULT_POSTS = [
    {
      id: 'why-short-stay-islamabad',
      slug: 'why-short-stay-islamabad',
      title: 'Why Short Stays in Islamabad Are Better Than Hotels',
      excerpt: 'Fully equipped kitchens, more space, privacy, and lower cost. Here\'s why furnished short stays are replacing hotels for business travelers and families.',
      author: 'Kor Da Team',
      date: '2025-01-15',
      image: 'https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?auto=format&fit=crop&w=800&q=75',
      category: 'tips',
      tags: ['islamabad', 'short-stay', 'travel']
    }
  ];

  window.BlogService = {
    getAll: async function() {
      if(cache) return cache;
      try {
        var res = await fetch('content/compiled/blog.json');
        if(res.ok) {
          var data = await res.json();
          if(Array.isArray(data) && data.length > 0) { cache = data; return cache; }
        }
      } catch(err) {
        console.warn('BlogService: JSON fetch failed, using fallback', err);
      }
      cache = DEFAULT_POSTS;
      return cache;
    },

    getBySlug: async function(slug) {
      var posts = await this.getAll();
      return posts.find(function(p){ return p.slug === slug; }) || null;
    },

    getByCategory: async function(category) {
      var posts = await this.getAll();
      if(!category || category === 'all') return posts;
      return posts.filter(function(p){ return p.category === category; });
    }
  };
})();
