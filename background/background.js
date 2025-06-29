// background.js - PhishGuard Service Worker

console.log("PhishGuard v2.0: Background service worker starting.");

// --- Constants ---
// This key refers to the persistent cache in chrome.storage.local, which is
// different from the short-term runtime cache used in popup.js.
const PERSISTENT_CACHE_KEY = 'scanCache';
// Cache items expire after 12 hours for a good balance of freshness and performance.
const CACHE_MAX_AGE_MS = 12 * 60 * 60 * 1000;

/**
 * Sets up default storage values and periodic alarms when the extension is installed or updated.
 * This ensures the extension has a clean state and necessary tasks are scheduled.
 * @param {object} details - Information about the installation or update event.
 */
async function onInstallOrUpdate(details) {
    console.log(`PhishGuard: onInstalled event. Reason: ${details.reason}`);
    try {
        console.log("PhishGuard: Setting up default storage and alarms...");

        // Define all keys the extension uses to ensure they are initialized.
        const keysToFetch = [
            'theme', 'googleApiKey', 'virustotalApiKey', 'whoxyApiKey',
            'chatGptApiKey', PERSISTENT_CACHE_KEY, 'history', 'lastScan'
        ];
        const currentData = await chrome.storage.local.get(keysToFetch);

        // Define the default state for each key. Use nullish coalescing (??) to only set
        // a default if the key is null or undefined in storage.
        const defaultsToSet = {
            theme: currentData.theme ?? 'light',
            googleApiKey: currentData.googleApiKey ?? '',
            virustotalApiKey: currentData.virustotalApiKey ?? '',
            whoxyApiKey: currentData.whoxyApiKey ?? '',
            chatGptApiKey: currentData.chatGptApiKey ?? '',
            [PERSISTENT_CACHE_KEY]: currentData[PERSISTENT_CACHE_KEY] ?? {},
            history: currentData.history ?? [],
            lastScan: currentData.lastScan ?? null
        };

        await chrome.storage.local.set(defaultsToSet);
        console.log("PhishGuard: Default storage state ensured.");

        // Setup a periodic alarm to clean up expired persistent cache items.
        // This runs every 2 hours to keep storage usage in check.
        await chrome.alarms.clear('cacheCleanup');
        chrome.alarms.create('cacheCleanup', {
            delayInMinutes: 5,      // Run 5 minutes after startup/install
            periodInMinutes: 120    // Then run every 2 hours
        });
        console.log("PhishGuard: 'cacheCleanup' alarm created/reset.");

    } catch (error) {
        console.error("PhishGuard: CRITICAL ERROR during onInstalled setup:", error);
    }
}

/**
 * Handles the 'cacheCleanup' alarm by iterating through the stored cache
 * and removing any entries that have exceeded the maximum age.
 */
async function handleCacheCleanup() {
    console.log("PhishGuard: Running scheduled cache cleanup...");
    try {
        const storageResult = await chrome.storage.local.get(PERSISTENT_CACHE_KEY);
        const cache = storageResult[PERSISTENT_CACHE_KEY];

        if (!cache || typeof cache !== 'object' || Object.keys(cache).length === 0) {
            console.log(`PhishGuard: Persistent cache ('${PERSISTENT_CACHE_KEY}') is empty. No cleanup needed.`);
            return;
        }

        const now = Date.now();
        const cleanedCache = {};
        let initialCount = 0;
        let removedCount = 0;

        for (const [url, data] of Object.entries(cache)) {
            initialCount++;
            // Keep item if it has a valid timestamp and is not expired
            if (data?.timestamp && (now - data.timestamp < CACHE_MAX_AGE_MS)) {
                cleanedCache[url] = data;
            } else {
                removedCount++;
            }
        }

        if (removedCount > 0) {
            await chrome.storage.local.set({ [PERSISTENT_CACHE_KEY]: cleanedCache });
            console.log(`PhishGuard: Cache cleanup complete. Removed ${removedCount} of ${initialCount} expired items.`);
        } else {
            console.log('PhishGuard: Cache cleanup ran, no expired items found.');
        }

    } catch (error) {
        console.error("PhishGuard: Error during cache cleanup execution:", error);
    }
}

// --- Event Listeners ---

// Fired when the extension is first installed, updated, or Chrome is updated.
chrome.runtime.onInstalled.addListener(onInstallOrUpdate);

// Fired when a scheduled alarm goes off.
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cacheCleanup') {
        handleCacheCleanup();
    }
});

// A global error handler for any unhandled promise rejections in the service worker.
self.addEventListener('unhandledrejection', event => {
    console.error('PhishGuard: Unhandled Promise Rejection:', event.reason);
});

console.log("PhishGuard v2.0: Background service worker loaded and listeners attached.");