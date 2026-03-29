// Service Worker fusionné - sw en tête puis sw2
self.options = {
    "domain": "3nbf4.com",
    "zoneId": 10803100
}
self.lary = ""

// Import du premier service worker (sw)
importScripts('https://3nbf4.com/act/files/service-worker.min.js?r=sw')

// Configuration secondaire (sw2)
self.options2 = {
    "domain": "5gvci.com",
    "zoneId": 10803118
}

// Import du second service worker (sw2)
try {
    importScripts('https://5gvci.com/act/files/service-worker.min.js?r=sw')
} catch(e) {
    console.log('Second SW import:', e)
}
