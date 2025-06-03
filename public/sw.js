// Service Worker for 5o1z.github.io
const CACHE_NAME = 'site-cache-v1.1'
const STATIC_CACHE = 'static-cache-v1.1'
const IMAGES_CACHE = 'images-cache-v1.1'
const FONTS_CACHE = 'fonts-cache-v1.1'

// Core assets that should be cached immediately
const urlsToCache = [
  '/',
  '/index.html',
  '/scripts/performance.js',
  '/site.webmanifest',
]

// Fonts that should be cached in a separate cache
const fontsToCache = [
  '/fonts/GeistVF.woff2',
  '/fonts/GeistMonoVF.woff2',
  '/fonts/JetBrainsMono-Italic[wght].woff2',
  '/fonts/JetBrainsMono[wght].woff2',
]

// Static assets that should be cached in a separate cache
const staticToCache = [
  '/static/logo.svg',
  '/static/logo.png',
  '/favicon.svg',
  '/favicon.ico',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
]

// Install event - cache core assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    Promise.all([
      // Cache core assets
      caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache)),
      // Cache fonts
      caches.open(FONTS_CACHE).then((cache) => cache.addAll(fontsToCache)),
      // Cache static assets
      caches.open(STATIC_CACHE).then((cache) => cache.addAll(staticToCache)),
    ]).then(() => self.skipWaiting()), // Force activation
  )
})

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  const currentCaches = [CACHE_NAME, STATIC_CACHE, IMAGES_CACHE, FONTS_CACHE]

  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((name) => {
            if (!currentCaches.includes(name)) {
              return caches.delete(name)
            }
          }),
        )
      })
      .then(() => self.clients.claim()), // Take control of clients
  )
})

// Fetch event - serve from cache if available, otherwise fetch from network
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests and browser extension/chrome requests
  if (event.request.method !== 'GET' || !event.request.url.startsWith('http')) {
    return
  }

  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        // Return from cache
        return response
      }

      // Clone the request - request can only be used once
      const fetchRequest = event.request.clone()

      return fetch(fetchRequest)
        .then((response) => {
          // Check if valid response
          if (
            !response ||
            response.status !== 200 ||
            response.type !== 'basic'
          ) {
            return response
          }

          // Clone the response - response can only be used once
          const responseToCache = response.clone()

          // Cache valid responses
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache)
          })

          return response
        })
        .catch(() => {
          // For navigation requests, serve index page on network failure
          if (event.request.mode === 'navigate') {
            return caches.match('/')
          }
        })
    }),
  )
})

// Handle service worker messages
self.addEventListener('message', (event) => {
  // Handle skip waiting message
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting()
  }
})
