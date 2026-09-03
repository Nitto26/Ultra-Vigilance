// background.js — AI-Shield MV3 Service Worker
// Evaluates all navigations and clicked links with the live FastAPI threat engine.

const LOCAL_ENDPOINT = "http://127.0.0.1:8000/scan-document";
const LOCAL_DOMAIN_ENDPOINT = "http://127.0.0.1:8000/scan-domain";
const TUNNEL_ENDPOINT = "https://mugwumpian-scottie-homely.ngrok-free.dev/scan-document";
const REQUEST_TIMEOUT_MS = 5000;

// In-memory cache for repeat link evaluations (TTL = 30 seconds)
const verdictCache = new Map();
const pendingScans = new Map();
const CACHE_TTL_MS = 30 * 1000;

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

async function fetchVerdict(endpoint, url, signal) {
    const response = await fetch(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true"
        },
        body: JSON.stringify({ url: url }),
        signal: signal
    });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
}

async function scanDomain(url) {
    if (!url || !/^https?:\/\//i.test(url)) {
        return { verdict: "SAFE", confidence: 0, reasons: [], display_reasons: [] };
    }

    const cached = getCached(url);
    if (cached) return cached;

    if (pendingScans.has(url)) {
        return pendingScans.get(url);
    }

    const scanPromise = (async () => {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        try {
            let verdict = null;
            try {
                verdict = await fetchVerdict(LOCAL_ENDPOINT, url, controller.signal);
            } catch (err1) {
                try {
                    verdict = await fetchVerdict(LOCAL_DOMAIN_ENDPOINT, url, controller.signal);
                } catch (err2) {
                    verdict = await fetchVerdict(TUNNEL_ENDPOINT, url, controller.signal);
                }
            }

            console.log(`[AI-Shield Background] Evaluated ${url} ->`, verdict?.verdict, `(${verdict?.confidence})`);
            setCached(url, verdict);
            return verdict;
        } catch (err) {
            console.warn(`[AI-Shield Background] Scan failed open for ${url}:`, err.message);
            return { verdict: "SAFE", confidence: 0, reasons: [], display_reasons: [] };
        } finally {
            clearTimeout(timeout);
            pendingScans.delete(url);
        }
    })();

    pendingScans.set(url, scanPromise);
    return scanPromise;
}

// Triggers instant UI notifications & sends payload to active tab
async function handleThreatVerdict(tabId, url, result) {
    if (!result || (result.verdict !== "FRAUD" && result.verdict !== "SUSPICIOUS")) return;

    const isFraud = result.verdict === "FRAUD";
    const riskPct = Math.round((result.confidence || 0) * 100);

    // 1. Set Toolbar Badge Alert
    if (tabId && chrome.action) {
        try {
            chrome.action.setBadgeText({ text: isFraud ? "🚨" : "⚠️", tabId });
            chrome.action.setBadgeBackgroundColor({ color: isFraud ? "#EF4444" : "#F59E0B", tabId });
        } catch (_) { }
    }

    // 2. Trigger Native Chrome Notification
    try {
        const primaryReason = (result.display_reasons && result.display_reasons.length > 0)
            ? result.display_reasons[0]
            : (result.reasons && result.reasons.length > 0 ? result.reasons[0] : "Potential Phishing Threat");

        chrome.notifications.create(`threat-${Date.now()}`, {
            type: "basic",
            iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='64' height='64'><rect width='64' height='64' rx='16' fill='%23EF4444'/><text x='50%' y='55%' font-size='32' text-anchor='middle' dominant-baseline='middle' fill='white'>🛡️</text></svg>",
            title: isFraud ? `🚨 UV Guard: Fraud Blocked (${riskPct}% Risk)` : `⚠️ UV Guard: Suspicious Link (${riskPct}% Risk)`,
            message: `${primaryReason}\nDestination: ${url}`,
            priority: 2
        });
    } catch (_) { }

    // 3. Broadcast to Content Script
    if (tabId) {
        const payload = {
            type: "AI_SHIELD_VERDICT",
            url: url,
            verdict: result.verdict,
            confidence: result.confidence,
            reasons: result.reasons || [],
            display_reasons: result.display_reasons || result.reasons || []
        };

        try {
            await chrome.tabs.sendMessage(tabId, payload);
        } catch (err) {
            // Tab was freshly loaded or navigating; inject content script directly
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: tabId },
                    files: ["content.js"]
                });
                setTimeout(() => {
                    chrome.tabs.sendMessage(tabId, payload).catch(() => { });
                }, 100);
            } catch (_) { }
        }
    }
}

// 1. On-demand message listener from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "SCAN_URL") {
        scanDomain(message.url).then(verdict => {
            if (sender.tab?.id && (verdict.verdict === "FRAUD" || verdict.verdict === "SUSPICIOUS")) {
                handleThreatVerdict(sender.tab.id, message.url, verdict);
            }
            sendResponse(verdict);
        }).catch(() => {
            sendResponse({ verdict: "SAFE", confidence: 0, reasons: [], display_reasons: [] });
        });
        return true;
    }
});

// 2. Navigation intent prefetch
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!/^https?:\/\//i.test(details.url)) return;
    const result = await scanDomain(details.url);
    if (result.verdict === "FRAUD" || result.verdict === "SUSPICIOUS") {
        handleThreatVerdict(details.tabId, details.url, result);
    }
});

// 3. Tab commit broadcast
chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!/^https?:\/\//i.test(details.url)) return;
    const result = await scanDomain(details.url);
    handleThreatVerdict(details.tabId, details.url, result);
});

// 4. Tab completed status listener
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && /^https?:\/\//i.test(tab.url)) {
        const result = await scanDomain(tab.url);
        handleThreatVerdict(tabId, tab.url, result);
    }
});