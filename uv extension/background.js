// background.js — AI-Shield MV3 service worker
// Watches top-level navigations, checks the target URL against the
// backend /scan-domain endpoint, and asks the content script to show
// a banner if the verdict isn't SAFE.

// TODO: point this at your FastAPI backend (ngrok URL during the demo).
const API_BASE_URL = "https://mugwumpian-scottie-homely.ngrok-free.dev";
const SCAN_ENDPOINT = `${API_BASE_URL}/scan-domain`;
const REQUEST_TIMEOUT_MS = 4000;

// Small in-memory cache so repeat navigations to the same URL within a
// session don't re-hit the backend every time.
const verdictCache = new Map();
const pendingScans = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

function getCached(url) {
    const entry = verdictCache.get(url);
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) {
        verdictCache.delete(url);
        return null;
    }
    return entry.verdict;
}

function setCached(url, verdict) {
    verdictCache.set(url, { verdict, ts: Date.now() });
}

async function scanDomain(url) {
    const cached = getCached(url);
    if (cached) return cached;

    if (pendingScans.has(url)) {
        return pendingScans.get(url);
    }

    const scanPromise = (async () => {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url }),
                signal: controller.signal
            });

            if (!response.ok) {
                throw new Error(`Backend returned ${response.status}`);
            }

            const verdict = await response.json();
            // Expected shape: { verdict: "SAFE"|"SUSPICIOUS"|"FRAUD", confidence: number, reasons: string[] }
            setCached(url, verdict);
            return verdict;
        } catch (err) {
            // Fail open: if the backend is unreachable or slow, don't block
            // browsing — just skip the warning for this navigation.
            console.warn("[AI-Shield] scan-domain failed, failing open:", err.message);
            return { verdict: "UNKNOWN", confidence: 0, reasons: ["scan unavailable"] };
        } finally {
            clearTimeout(timeout);
            pendingScans.delete(url);
        }
    })();

    pendingScans.set(url, scanPromise);
    return scanPromise;
}

// 1. Warm-up prefetch on navigation intent
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only care about top-level frames and http(s) URLs
    if (details.frameId !== 0) return;
    if (!/^https?:\/\//i.test(details.url)) return;

    // Start scan early to warm cache while browser handles TLS and fetch
    scanDomain(details.url);
});

// 2. Once the page is committed and content script is injected, push verdict
chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!/^https?:\/\//i.test(details.url)) return;

    const result = await scanDomain(details.url);

    if (result.verdict === "FRAUD" || result.verdict === "SUSPICIOUS") {
        try {
            await chrome.tabs.sendMessage(details.tabId, {
                type: "AI_SHIELD_VERDICT",
                url: details.url,
                verdict: result.verdict,
                confidence: result.confidence,
                reasons: result.reasons || []
            });
        } catch (err) {
            // Content script will pull via GET_VERDICT on load if message isn't caught here
        }
    }
});

// 3. Handle pull requests from content.js (avoids any navigation race condition)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "GET_VERDICT") {
        const targetUrl = message.url || sender.tab?.url;
        if (!targetUrl) {
            sendResponse({ verdict: "UNKNOWN", confidence: 0, reasons: ["No URL provided"] });
            return;
        }

        scanDomain(targetUrl)
            .then((result) => sendResponse(result))
            .catch((err) => {
                sendResponse({ verdict: "UNKNOWN", confidence: 0, reasons: [err.message] });
            });

        return true; // Keep channel open for async sendResponse
    }
});