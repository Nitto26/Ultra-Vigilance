// content.js — AI-Shield Top Security Navigation Bar
// Injects a high-visibility, full-width colored alert navbar directly
// underneath the browser's URL address bar whenever a threat is flagged.

const HOST_ID = "ai-shield-top-bar-host";

const CODE_TO_TEXT = {
    "known_trusted_domain": "This is a well-known, trusted website.",
    "brand_name_in_subdomain": "This web address is trying to look like a bank or well-known company, but isn't their real site.",
    "urgency_keyword_in_subdomain": "This web address uses urgent language often used to pressure people into acting quickly.",
    "newly_registered_domain": "This website was registered very recently — often a sign of a scam site set up quickly.",
    "hosted_on_shared_platform": "This site is hosted on a free shared platform and contains suspicious patterns.",
    "shortened_url_expanded": "This was a shortened link that redirects to a flagged destination.",
    "shortened_url_unresolvable": "We couldn't verify where this shortened link actually leads.",
    "high_risk_tld": "Uses an obscure or high-risk domain extension commonly associated with phishing campaigns.",
    "homoglyph_obfuscation": "Uses lookalike characters or excessive hyphens to mimic legitimate domains.",
    "suspicious_keywords": "Contains banking, verification, or credential-harvesting keywords.",
    "insecure_connection": "Insecure connection protocol (No HTTPS encryption).",
    "cross_channel_lure": "Previously observed in a suspicious message or payment fraud attempt."
};

function formatReason(code) {
    if (!code) return "";
    if (CODE_TO_TEXT[code]) return CODE_TO_TEXT[code];

    if (code.startsWith("impersonates_")) {
        const brand = code.replace("impersonates_", "").toUpperCase();
        return `This site appears to be impersonating ${brand}.`;
    }
    if (code.startsWith("domain_age_")) {
        const days = code.replace("domain_age_", "").replace("_days", "");
        return `This website is only ${days} days old.`;
    }
    if (code.includes(" ") && !code.includes("_")) {
        return code;
    }
    return code.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()) + " detected.";
}

function removeTopNavBar() {
    const existingHost = document.getElementById(HOST_ID);
    if (existingHost) existingHost.remove();
}

function renderTopSecurityNavBar({ targetUrl, verdict, confidence, reasons, displayReasons }) {
    removeTopNavBar();

    const isFraud = verdict === "FRAUD";
    const pct = Math.round((confidence || 0) * 100);

    // Theme Gradients & Glows
    const navGradient = isFraud
        ? "linear-gradient(90deg, #7f1d1d 0%, #b91c1c 25%, #dc2626 50%, #991b1b 100%)"
        : "linear-gradient(90deg, #78350f 0%, #b45309 25%, #d97706 50%, #92400e 100%)";
    const borderColor = isFraud ? "#f87171" : "#fbbf24";
    const glowShadow = isFraud
        ? "0 4px 25px rgba(220, 38, 38, 0.6), 0 1px 3px rgba(0, 0, 0, 0.8)"
        : "0 4px 25px rgba(217, 119, 6, 0.6), 0 1px 3px rgba(0, 0, 0, 0.8)";
    const badgeColor = isFraud ? "#fecaca" : "#fef3c7";
    const badgeBg = isFraud ? "rgba(153, 27, 27, 0.75)" : "rgba(146, 64, 14, 0.75)";

    // 1. Create Isolated Host Element
    const host = document.createElement("div");
    host.id = HOST_ID;
    Object.assign(host.style, {
        all: "initial",
        position: "fixed",
        top: "0",
        left: "0",
        right: "0",
        width: "100vw",
        zIndex: "2147483647",
        display: "block",
        boxSizing: "border-box"
    });

    // 2. Attach Shadow DOM (Protects against host page CSS overrides)
    const shadow = host.attachShadow({ mode: "open" });

    // 3. Shadow DOM Styles
    const style = document.createElement("style");
    style.textContent = `
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        @keyframes aiShieldSlideDown {
            from { transform: translateY(-100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        @keyframes aiPulseGlow {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.85; transform: scale(1.03); }
        }
        .ai-nav-bar {
            width: 100%;
            background: ${navGradient};
            border-bottom: 2px solid ${borderColor};
            box-shadow: ${glowShadow};
            color: #ffffff;
            animation: aiShieldSlideDown 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
        }
        .ai-nav-main {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 18px;
            gap: 16px;
            flex-wrap: nowrap;
        }
        .ai-left-group {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
            flex: 1;
        }
        .ai-shield-icon {
            font-size: 22px;
            animation: aiPulseGlow 2s infinite ease-in-out;
            flex-shrink: 0;
        }
        .ai-badge {
            background: ${badgeBg};
            color: ${badgeColor};
            border: 1px solid ${borderColor};
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.6px;
            padding: 4px 8px;
            border-radius: 6px;
            text-transform: uppercase;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .ai-score-pill {
            background: rgba(0, 0, 0, 0.4);
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 20px;
            white-space: nowrap;
            flex-shrink: 0;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .ai-message {
            font-size: 13px;
            font-weight: 600;
            color: #ffffff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        }
        .ai-url-preview {
            font-size: 11px;
            color: rgba(255, 255, 255, 0.85);
            background: rgba(0, 0, 0, 0.25);
            padding: 2px 6px;
            border-radius: 4px;
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
        }
        .ai-right-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-shrink: 0;
        }
        .ai-btn {
            border: none;
            border-radius: 7px;
            font-weight: 700;
            font-size: 12px;
            cursor: pointer;
            padding: 6px 12px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: transform 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
            white-space: nowrap;
        }
        .ai-btn:active {
            transform: scale(0.97);
        }
        .ai-btn-safe {
            background: #10b981;
            color: #042f2e;
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.4);
        }
        .ai-btn-safe:hover {
            background: #34d399;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.6);
        }
        .ai-btn-proceed {
            background: rgba(0, 0, 0, 0.35);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.35);
        }
        .ai-btn-proceed:hover {
            background: rgba(0, 0, 0, 0.55);
            border-color: rgba(255, 255, 255, 0.6);
        }
        .ai-btn-toggle {
            background: rgba(0, 0, 0, 0.25);
            color: #ffffff;
            font-size: 11px;
            padding: 6px 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .ai-btn-toggle:hover {
            background: rgba(0, 0, 0, 0.4);
        }
        .ai-btn-close {
            background: transparent;
            color: rgba(255, 255, 255, 0.7);
            border: none;
            font-size: 16px;
            padding: 4px 8px;
            cursor: pointer;
            line-height: 1;
        }
        .ai-btn-close:hover {
            color: #ffffff;
        }
        .ai-drawer {
            max-height: 0;
            overflow: hidden;
            background: rgba(15, 23, 42, 0.96);
            backdrop-filter: blur(16px);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            transition: max-height 0.3s cubic-bezier(0.16, 1, 0.3, 1), padding 0.3s ease;
            padding: 0 20px;
        }
        .ai-drawer.open {
            max-height: 280px;
            padding: 12px 20px 16px 20px;
            border-bottom: 2px solid ${borderColor};
        }
        .ai-drawer-title {
            font-size: 11px;
            font-weight: 800;
            color: ${borderColor};
            letter-spacing: 0.6px;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .ai-reasons-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 8px;
        }
        .ai-reason-pill {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 11px;
            color: #e2e8f0;
            display: flex;
            align-items: flex-start;
            gap: 6px;
            line-height: 1.35;
        }
        .ai-bullet {
            color: ${borderColor};
            font-weight: bold;
            flex-shrink: 0;
        }
    `;
    shadow.appendChild(style);

    // 4. Build Navigation Bar Elements
    const rawList = (displayReasons && displayReasons.length > 0) ? displayReasons : (reasons || []);
    const formattedReasons = rawList.map(r => formatReason(r)).filter(r => r.length > 0);
    const primaryReason = formattedReasons[0] || (isFraud ? "High-risk fraudulent domain detected." : "Suspicious domain markers observed.");

    const navBar = document.createElement("div");
    navBar.className = "ai-nav-bar";

    navBar.innerHTML = `
        <div class="ai-nav-main">
            <div class="ai-left-group">
                <span class="ai-shield-icon">${isFraud ? "🚨" : "⚠️"}</span>
                <span class="ai-badge">${isFraud ? "AI-Shield: Fraud Blocked" : "AI-Shield: Suspicious Link"}</span>
                <span class="ai-score-pill">Risk: ${pct}%</span>
                <span class="ai-message">${primaryReason}</span>
                ${targetUrl ? `<span class="ai-url-preview" title="${targetUrl}">${targetUrl}</span>` : ""}
            </div>
            <div class="ai-right-group">
                ${formattedReasons.length > 0 ? `<button class="ai-btn ai-btn-toggle" id="ai-toggle-btn">Why Flagged? ▾</button>` : ""}
                <button class="ai-btn ai-btn-safe" id="ai-safe-btn">🛡️ Back to Safety</button>
                <button class="ai-btn ai-btn-proceed" id="ai-proceed-btn">⚠️ Proceed Anyway</button>
                <button class="ai-btn-close" id="ai-close-btn" title="Dismiss Banner">✕</button>
            </div>
        </div>
        <div class="ai-drawer" id="ai-drawer">
            <div class="ai-drawer-title">Detailed Threat Analysis & Reasons:</div>
            <div class="ai-reasons-grid">
                ${formattedReasons.map(r => `
                    <div class="ai-reason-pill">
                        <span class="ai-bullet">•</span>
                        <span>${r}</span>
                    </div>
                `).join("")}
            </div>
        </div>
    `;

    // 5. Connect Interactive Handlers
    const drawer = navBar.querySelector("#ai-drawer");
    const toggleBtn = navBar.querySelector("#ai-toggle-btn");
    if (toggleBtn && drawer) {
        toggleBtn.addEventListener("click", () => {
            const isOpen = drawer.classList.toggle("open");
            toggleBtn.textContent = isOpen ? "Hide Details ▴" : "Why Flagged? ▾";
        });
    }

    const safeBtn = navBar.querySelector("#ai-safe-btn");
    safeBtn.addEventListener("click", () => {
        host.remove();
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = "about:blank";
        }
    });

    const proceedBtn = navBar.querySelector("#ai-proceed-btn");
    proceedBtn.addEventListener("click", () => {
        host.remove();
        if (targetUrl && targetUrl !== window.location.href) {
            window.location.href = targetUrl;
        }
    });

    const closeBtn = navBar.querySelector("#ai-close-btn");
    closeBtn.addEventListener("click", () => {
        host.remove();
    });

    shadow.appendChild(navBar);

    // 6. Mount to Page
    const mount = () => {
        const target = document.body || document.documentElement;
        if (target && !document.getElementById(HOST_ID)) {
            target.appendChild(host);
        }
    };

    mount();
    if (!document.body) {
        document.addEventListener("DOMContentLoaded", mount, { once: true });
    }
}

// =========================================================================
// Proactive Page URL Scanner
// =========================================================================
function evaluateCurrentPage() {
    const currentUrl = window.location.href;
    if (!currentUrl || !/^https?:\/\//i.test(currentUrl)) return;

    try {
        chrome.runtime.sendMessage({ type: "SCAN_URL", url: currentUrl }, (response) => {
            if (response && (response.verdict === "FRAUD" || response.verdict === "SUSPICIOUS")) {
                console.log("[AI-Shield Content] Showing Top Alert Navbar for:", currentUrl, response);
                renderTopSecurityNavBar({
                    targetUrl: currentUrl,
                    verdict: response.verdict,
                    confidence: response.confidence,
                    reasons: response.reasons,
                    displayReasons: response.display_reasons
                });
            }
        });
    } catch (e) {
        // Extension context refreshed
    }
}

evaluateCurrentPage();
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", evaluateCurrentPage, { once: true });
}
window.addEventListener("load", evaluateCurrentPage, { once: true });

// =========================================================================
// In-Page Click Interceptor (Capture Phase)
// =========================================================================
document.addEventListener("click", (event) => {
    const anchor = event.target.closest("a");
    if (!anchor) return;

    const href = anchor.href;
    if (!href || !/^https?:\/\//i.test(href)) return;

    event.preventDefault();
    event.stopPropagation();

    try {
        chrome.runtime.sendMessage({ type: "SCAN_URL", url: href }, (response) => {
            const verdict = response?.verdict || "SAFE";

            if (verdict === "FRAUD" || verdict === "SUSPICIOUS") {
                renderTopSecurityNavBar({
                    targetUrl: href,
                    verdict: verdict,
                    confidence: response.confidence,
                    reasons: response.reasons,
                    displayReasons: response.display_reasons
                });
            } else {
                window.location.href = href;
            }
        });
    } catch (e) {
        window.location.href = href;
    }
}, true);

// =========================================================================
// Service Worker Push Broadcast Listener
// =========================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "AI_SHIELD_VERDICT") {
        if (message.verdict === "FRAUD" || message.verdict === "SUSPICIOUS") {
            renderTopSecurityNavBar({
                targetUrl: message.url,
                verdict: message.verdict,
                confidence: message.confidence,
                reasons: message.reasons,
                displayReasons: message.display_reasons
            });
        }
    }
    sendResponse({ received: true });
});