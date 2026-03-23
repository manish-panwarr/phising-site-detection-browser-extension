
// --- Global Helper ---
/**
 * Updates the visual properties of a CSS conic-gradient progress circle.
 */
window.updateProgressCircle = (element, percent, color) => {
    if (!element) return;
    const clampedPercent = Math.min(100, Math.max(0, percent));
    element.style.setProperty('--progress', `${clampedPercent}`);
    if (color) element.style.setProperty('--color', color);
};

// --- Configuration & State ---
const CONFIG = {
    CACHE_DURATION: 5 * 60 * 1000,
    SCAN_STEPS: 8,
    MAX_HISTORY_ITEMS: 20,
    ERROR_DISPLAY_DURATION: 7000,
    PHISHING_THRESHOLD: 72, // score above this shows the full-width warning
};

const state = {
    currentUrl: '',
    currentTabTitle: '',
    scanResults: null,
    apiStatus: 'ready',
    history: [],
    errorTimeoutId: null,
    riskChart: null,
};

// --- DOM Element Cache ---
const elements = {};
function cacheElements() {
    const ids = [
        'url-input', 'check-btn', 'current-tab-btn', 'history-btn', 'settings-btn',
        'loading', 'loading-message', 'progress-fill', 'main-content',
        'overall-score-progress', 'overall-score-text',
        'risk-indicator', 'risk-pill', 'status-badge', 'status-badge-text',
        'details-content', 'report-content', 'intent-content',
        'toggle-details', 'toggle-report', 'toggle-intent',
        'toggle-chart', 'toggle-alerts',
        'last-scan', 'scan-time', 'theme-switch', 'error-display',
        'alerts-card', 'alerts-content', 'actions-bar',
        'report-btn', 'recheck-btn', 'trust-btn',
        'phishing-warning-overlay', 'overlay-domain-text', 'overlay-risk-score',
        'overlay-back-btn', 'overlay-proceed-btn',
        'risk-chart', 'donut-score',
        'leg-domain', 'leg-content', 'leg-blacklist',
        'stat-domain-age-val', 'stat-https-val', 'stat-blacklist-val', 'stat-vt-val',
    ];
    ids.forEach(id => {
        const key = id.replace(/-([\w])/g, (_, c) => c.toUpperCase());
        elements[key] = document.getElementById(id);
    });
    if (elements.riskIndicator) {
        elements.riskIndicatorBar = elements.riskIndicator.querySelector('.indicator-bar');
    }
}

// --- Initialization ---
document.addEventListener('DOMContentLoaded', async () => {
    cacheElements();
    setupEventListeners();
    await loadSettings();
    await loadHistory();
    await loadLastScan();
});

function setupEventListeners() {
    elements.checkBtn?.addEventListener('click', handleCheckUrl);
    elements.currentTabBtn?.addEventListener('click', handleCurrentTab);
    elements.historyBtn?.addEventListener('click', showHistoryModal);
    elements.settingsBtn?.addEventListener('click', openOptionsPage);
    elements.urlInput?.addEventListener('keypress', e => { if (e.key === 'Enter') handleCheckUrl(); });

    elements.toggleDetails?.addEventListener('click', () => toggleSection(elements.detailsContent, elements.toggleDetails));
    elements.toggleReport?.addEventListener('click', () => toggleSection(elements.reportContent, elements.toggleReport));
    elements.toggleIntent?.addEventListener('click', () => toggleSection(elements.intentContent, elements.toggleIntent));
    elements.toggleChart?.addEventListener('click', () => {
        const c = document.getElementById('chart-content');
        toggleSection(c, elements.toggleChart);
    });
    elements.toggleAlerts?.addEventListener('click', () => toggleSection(elements.alertsContent, elements.toggleAlerts));
    elements.themeSwitch?.addEventListener('change', toggleTheme);

    // Actions
    elements.reportBtn?.addEventListener('click', handleReportSite);
    elements.recheckBtn?.addEventListener('click', handleRecheck);
    elements.trustBtn?.addEventListener('click', handleTrustSite);

    // Overlay actions
    elements.overlayBackBtn?.addEventListener('click', () => {
        hidePhishingOverlay();
        chrome.tabs.goBack?.();
    });
    elements.overlayProceedBtn?.addEventListener('click', hidePhishingOverlay);
}

// --- Event Handlers ---
async function handleCheckUrl() {
    const url = elements.urlInput?.value?.trim();
    if (!url) return showError('Please enter a URL.');
    const validation = isValidUrl(url);
    if (!validation.valid) return showError(validation.message);
    state.currentUrl = validation.url;
    state.currentTabTitle = 'Manual Entry';
    elements.urlInput.value = state.currentUrl;
    await scanWebsite(state.currentUrl);
}

async function handleCurrentTab() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url || !tab.url.startsWith('http')) {
            return showError('Cannot scan the current tab (invalid or non-web URL).');
        }
        const validation = isValidUrl(tab.url);
        if (!validation.valid) return showError(validation.message);
        elements.urlInput.value = validation.url;
        state.currentUrl = validation.url;
        state.currentTabTitle = tab.title || 'No Title';
        await scanWebsite(state.currentUrl);
    } catch (error) {
        console.error("Error getting current tab:", error);
        showError('Failed to access current tab. Check permissions.');
    }
}

function openOptionsPage() {
    chrome.runtime.openOptionsPage?.();
}

function handleReportSite() {
    if (!state.currentUrl) return showError('No site to report.');
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(state.currentUrl)}`;
    chrome.tabs.create({ url: reportUrl });
}

async function handleRecheck() {
    if (!state.currentUrl) return showError('No site to recheck.');
    // Clear cache for this URL
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');
    delete scanCache[state.currentUrl];
    await chrome.storage.local.set({ scanCache });
    await scanWebsite(state.currentUrl);
}

function handleTrustSite() {
    if (!state.currentUrl) return;
    chrome.storage.local.get({ trustedSites: [] }, ({ trustedSites }) => {
        if (!trustedSites.includes(state.currentUrl)) {
            trustedSites.push(state.currentUrl);
            chrome.storage.local.set({ trustedSites });
        }
    });
    hidePhishingOverlay();
    updateStatusBadge('safe');
    showError('Site marked as trusted. ✓');
}

// --- Core Scan Logic ---
async function scanWebsite(url) {
    if (state.apiStatus === 'loading') return;
    const scanStartTime = Date.now();
    state.apiStatus = 'loading';
    showLoading(true, 'Initiating analysis…');
    clearError();
    hidePhishingOverlay();
    resetUIForScan();

    try {
        updateProgress(1, 'Validating URL…');
        const domain = extractDomainFromUrl(url);
        if (!domain) throw new Error("Could not extract a valid domain.");

        updateProgress(2, 'Checking cache…');
        const cached = await getFromCache(url);
        if (cached) {
            console.log("PhishGuard: Using cached results for:", url);
            state.scanResults = cached;
            if (window.phishGuardWhois) {
                window.phishGuardWhois.updateDomainAgeMetricUI(cached.whoisResult);
            }
            updateUI(false);
            return;
        }

        updateProgress(3, 'Fetching API keys…');
        const apiKeys = await chrome.storage.local.get(['googleApiKey', 'virustotalApiKey', 'whoxyApiKey', 'chatGptApiKey']);

        updateProgress(4, 'Checking Google Safe Browsing…');
        const safeBrowsingPromise = apiKeys.googleApiKey ? checkGoogleSafeBrowsing(url, apiKeys.googleApiKey) : Promise.resolve({ error: 'API key missing' });

        updateProgress(5, 'Querying VirusTotal…');
        const virustotalPromise = apiKeys.virustotalApiKey ? checkVirusTotal(url, apiKeys.virustotalApiKey) : Promise.resolve({ error: 'API key missing' });

        updateProgress(6, 'Analyzing URL & SSL…');
        const sslPromise = checkSslCertificate(url);
        const urlAnalysisResult = analyzeUrlStructure(url);

        const [safeBrowsingResult, virustotalResult, sslResult] = await Promise.all([safeBrowsingPromise, virustotalPromise, sslPromise]);

        updateProgress(7, 'Fetching domain info (WHOIS)…');
        let whoisResult = { error: 'WHOIS module not loaded' };
        if (window.phishGuardWhois) {
            whoisResult = await window.phishGuardWhois.fetchAndDisplayDomainAge(domain, apiKeys.whoxyApiKey);
        }

        let preliminaryResults = { url, safeBrowsing: safeBrowsingResult, virustotal: virustotalResult, whoisResult, sslResult, urlAnalysis: urlAnalysisResult };

        updateProgress(8, 'AI phishing analysis…');
        const intentPrompt = generateAIPrompt(preliminaryResults);
        const intentAnalysisResult = apiKeys.chatGptApiKey
            ? await analyzeWithAI(intentPrompt, apiKeys.chatGptApiKey)
            : { error: 'OpenAI/OpenRouter API key not configured in settings.' };

        const scanEndTime = Date.now();
        state.scanResults = {
            ...preliminaryResults,
            intentAnalysis: intentAnalysisResult,
            timestamp: scanEndTime,
            scanTime: (scanEndTime - scanStartTime) / 1000,
        };
        state.scanResults.riskScore = calculateOverallRiskScore(state.scanResults);

        await saveToCache(url, state.scanResults);
        updateUI(true);

    } catch (error) {
        console.error("PhishGuard Scan Failed:", error);
        showError(`Scan failed: ${error.message}`);
        resetUI();
    } finally {
        state.apiStatus = 'ready';
        showLoading(false);
    }
}

// --- API & Analysis Functions ---
async function checkGoogleSafeBrowsing(url, apiKey) {
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const payload = {
        client: { clientId: "phishguard-pro", clientVersion: "2.0" },
        threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }] }
    };
    const response = await fetch(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'Google API Error');
    return { isSafe: !data.matches, threats: data.matches?.map(m => m.threatType) || [] };
}

async function checkVirusTotal(url, apiKey) {
    const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers: { 'x-apikey': apiKey } });
    if (response.status === 404) return { error: 'URL not found in VirusTotal database' };
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'VirusTotal API Error');
    const stats = data.data?.attributes?.last_analysis_stats || {};
    return {
        isSafe: (stats.malicious || 0) === 0 && (stats.suspicious || 0) === 0,
        maliciousCount: stats.malicious || 0,
        suspiciousCount: stats.suspicious || 0,
        harmlessCount: stats.harmless || 0,
        lastAnalysisDate: data.data?.attributes?.last_analysis_date ? new Date(data.data.attributes.last_analysis_date * 1000) : null,
    };
}

/**
 * Generates the structured AI prompt for phishing detection.
 */
function generateAIPrompt(results) {
    const { url, safeBrowsing, virustotal, whoisResult, sslResult, urlAnalysis } = results;

    const get = (value, fallback = 'N/A') => value ?? fallback;
    const sanitize = (str) => String(str).replace(/\[/g, '(').replace(/\]/g, ')');

    const promptData = {
        domain: get(extractDomainFromUrl(url)),
        sslValid: sslResult?.isValid ? 'Yes' : (sslResult?.isValid === false ? 'No' : 'Unknown'),
        whoisRegistered: sanitize(get(whoisResult?.formatted_create_date)),
        whoisAge: sanitize(get(whoisResult?.domainAgeString)),
        vtDetections: `${get(virustotal?.maliciousCount, 0)} malicious, ${get(virustotal?.suspiciousCount, 0)} suspicious`,
        gsbStatus: safeBrowsing?.isSafe ? 'Safe' : `Threats found: ${get(safeBrowsing?.threats?.join(', '), 'Unknown')}`,
        urlKeywords: urlAnalysis?.hasSuspiciousKeywords ? 'Yes' : 'No',
        urlSuspiciousTld: urlAnalysis?.isSuspiciousTld ? 'Yes' : 'No',
        similarToBrand: get(urlAnalysis?.similarToBrand, 'Unknown'),
        fullUrl: get(url)
    };

    return `You are a cybersecurity assistant specialized in phishing detection.

Strict Rules:
- Use ONLY the provided metadata.
- Do NOT assume or imagine website content.
- Output must be SHORT, precise, and structured.
- No explanations longer than 1 line.
- No paragraphs. Only bullet points.
- Avoid generic text.

Main Task:
Evaluate phishing risk with HIGH sensitivity to:
- Brand impersonation (Amazon, Google, SBI, PayPal, Microsoft, etc.)
- Typosquatting (misspellings like amaz0n, g00gle, paypa1)
- Suspicious domains and TLDs
- Newly registered domains

Website URL: ${promptData.fullUrl}

--- METADATA ---
- Safe Browsing: ${promptData.gsbStatus}
- VirusTotal: ${promptData.vtDetections}
- Domain Age: ${promptData.whoisAge}
- SSL: ${promptData.sslValid}
- Keywords: ${promptData.urlKeywords}
- Suspicious TLD: ${promptData.urlSuspiciousTld}
- Brand Similarity: ${promptData.similarToBrand}
--- END ---

Output Format (STRICT):

Impersonation Risk:
- High / Medium / Low (one line reason)

Top Signals:
- Max 3 bullets (very short, data-driven)

Risk Score:
- Number (0–100)

Verdict:
- SAFE / SUSPICIOUS / PHISHING (one line only)

Confidence:
- High / Medium / Low`.trim();
}

async function analyzeWithAI(prompt, apiKey) {
    const apiUrl = 'https://openrouter.ai/api/v1/chat/completions';
    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                'HTTP-Referer': chrome.runtime.getURL('popup.html'),
                'X-Title': 'PhishGuard Extension'
            },
            body: JSON.stringify({
                model: "mistralai/mistral-7b-instruct",
                messages: [{ role: "user", content: prompt }],
                temperature: 0.2,
                max_tokens: 320
            })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error?.message || 'OpenRouter API request failed');
        }
        return {
            text: data.choices[0]?.message?.content?.trim() || 'AI returned an empty response.'
        };
    } catch (error) {
        console.error("AI Analysis Error:", error);
        return { error: `AI analysis failed: ${error.message}` };
    }
}

function checkSslCertificate(url) {
    try {
        const urlObj = new URL(url);
        if (urlObj.protocol === 'https:') return { isValid: true, detail: 'Uses secure HTTPS' };
        if (urlObj.protocol === 'http:')  return { isValid: false, error: 'Site uses insecure HTTP' };
        return { isValid: null, error: `Unsupported protocol: ${urlObj.protocol}` };
    } catch {
        return { isValid: false, error: 'Invalid URL for SSL check' };
    }
}

function analyzeUrlStructure(url) {
    try {
        const urlObj = new URL(url);
        const suspiciousTlds = ['.xyz', '.top', '.info', '.loan', '.buzz', '.tk', '.biz', '.win', '.link', '.gq', '.ml', '.cf'];
        const suspiciousKeywords = ['login', 'signin', 'verify', 'account', 'update', 'secure', 'confirm', 'support', 'password', 'bank', 'paypal', 'microsoft', 'amazon', 'google', 'apple'];
        const brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'sbi', 'instagram', 'twitter'];
        const hostname = urlObj.hostname.replace(/^www\./, '');
        const similarToBrand = brands.find(b => {
            if (hostname.includes(b) && hostname !== b && !hostname.endsWith(`.${b}.com`)) return true;
            // Levenshtein-lite: common typosquatting chars
            const cleaned = hostname.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a');
            if (cleaned.includes(b) && cleaned !== hostname) return true;
            return false;
        }) || null;

        return {
            isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
            isSuspiciousTld: suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld)),
            hasManySubdomains: (urlObj.hostname.match(/\./g) || []).length > 2,
            hasSuspiciousKeywords: suspiciousKeywords.some(kw => url.toLowerCase().includes(kw)),
            similarToBrand,
        };
    } catch {
        return {};
    }
}

function calculateOverallRiskScore(results) {
    if (!results) return 0;
    let score = 0;
    const { safeBrowsing, virustotal, whoisResult, sslResult, urlAnalysis } = results;

    if (safeBrowsing?.isSafe === false) score += 60;
    if (virustotal?.isSafe === false && virustotal.maliciousCount > 0) score += (50 + Math.min(25, virustotal.maliciousCount * 2));
    if (urlAnalysis?.isIpAddress) score += 40;
    if (sslResult?.isValid === false) score += 30;
    if (virustotal?.suspiciousCount > 0) score += (20 + Math.min(15, virustotal.suspiciousCount * 2));
    if (urlAnalysis?.hasSuspiciousKeywords) score += 15;
    if (urlAnalysis?.isSuspiciousTld) score += 15;
    if (urlAnalysis?.similarToBrand) score += 25;
    if (whoisResult && whoisResult.domainAgeScore < 40) score += 15;
    else if (whoisResult && whoisResult.domainAgeScore < 80) score += 5;

    if (safeBrowsing?.isSafe && virustotal?.isSafe && sslResult?.isValid && whoisResult && whoisResult.domainAgeScore > 80) score -= 10;

    return Math.min(100, Math.max(0, Math.round(score)));
}

// --- UI Update Functions ---
async function updateUI(saveHistory = true) {
    if (!state.scanResults) return resetUI();
    const { riskScore, timestamp, scanTime } = state.scanResults;
    const riskLevel = riskScore > 70 ? 'danger' : riskScore > 40 ? 'warning' : 'safe';
    const scoreColor = `var(--${riskLevel}-color)`;

    // Trust score circle
    window.updateProgressCircle(elements.overallScoreProgress, riskScore, scoreColor);
    elements.overallScoreText.innerHTML = `${riskScore}<span>%</span>`;

    // Risk indicator bar
    if (elements.riskIndicatorBar) elements.riskIndicatorBar.style.setProperty('--position', `${riskScore}`);

    // Risk pill
    updateRiskPill(riskLevel, riskScore);

    // Status badge
    updateStatusBadge(riskLevel);

    // Quick stats
    updateQuickStats();

    // Donut chart
    updateDonutChart();

    // Details, report, AI, alerts
    updateDetailsContent();
    updateReportContent();
    updateIntentContent();
    updateAlertsSection();

    // Show/hide actions bar
    if (elements.actionsBar) elements.actionsBar.style.display = 'flex';

    // Timestamps
    elements.lastScan.textContent = formatDate(timestamp, true);
    elements.scanTime.textContent = `${(scanTime || 0).toFixed(1)}s`;
    elements.mainContent.style.display = 'flex';

    // Phishing warning overlay
    if (riskScore >= CONFIG.PHISHING_THRESHOLD) {
        showPhishingOverlay(riskScore, state.currentUrl);
    }

    if (saveHistory) await addToHistory(state.scanResults);
    chrome.storage.local.set({ lastScan: state.scanResults }).catch(console.error);
}

function updateRiskPill(riskLevel, riskScore) {
    if (!elements.riskPill) return;
    const labels = { safe: 'Low Risk', warning: 'Medium Risk', danger: 'High Risk' };
    elements.riskPill.textContent = labels[riskLevel] || 'Unknown';
    elements.riskPill.className = `risk-pill ${riskLevel}`;
}

function updateStatusBadge(riskLevel) {
    if (!elements.statusBadge) return;
    const labels = { safe: 'Safe', warning: 'Suspicious', danger: 'Dangerous', ready: 'Ready' };
    elements.statusBadge.className = `status-badge ${riskLevel}`;
    if (elements.statusBadgeText) elements.statusBadgeText.textContent = labels[riskLevel] || 'Ready';
}

function updateQuickStats() {
    const { sslResult, virustotal, safeBrowsing, whoisResult } = state.scanResults;

    // HTTPS
    const httpsVal = elements.statHttpsVal;
    if (httpsVal) {
        httpsVal.textContent = sslResult?.isValid ? 'Secure' : 'Insecure';
        httpsVal.className = `stat-value ${sslResult?.isValid ? 'safe' : 'danger'}`;
    }

    // Domain Age
    const ageVal = elements.statDomainAgeVal;
    if (ageVal) {
        ageVal.textContent = whoisResult?.domainAgeString || '—';
        const ageScore = whoisResult?.domainAgeScore || 0;
        ageVal.className = `stat-value ${ageScore > 60 ? 'safe' : ageScore > 20 ? 'warning' : 'danger'}`;
    }

    // Blacklist (Google Safe Browsing)
    const blVal = elements.statBlacklistVal;
    if (blVal) {
        blVal.textContent = safeBrowsing?.isSafe ? 'Clean' : 'Flagged';
        blVal.className = `stat-value ${safeBrowsing?.isSafe ? 'safe' : 'danger'}`;
    }

    // VirusTotal
    const vtVal = elements.statVtVal;
    if (vtVal) {
        const mal = virustotal?.maliciousCount || 0;
        const sus = virustotal?.suspiciousCount || 0;
        vtVal.textContent = virustotal?.error ? 'N/A' : `${mal} / ${sus}`;
        vtVal.className = `stat-value ${mal > 0 ? 'danger' : sus > 0 ? 'warning' : 'safe'}`;
    }
}

/**
 * Draws the risk breakdown donut chart on canvas.
 */
function updateDonutChart() {
    const canvas = elements.riskChart;
    if (!canvas) return;

    const { safeBrowsing, virustotal, whoisResult, sslResult, urlAnalysis, riskScore } = state.scanResults;

    // Calculate segment scores
    // Domain risk: domain age + TLD + IP + brand impersonation
    let domainRisk = 0;
    if (urlAnalysis?.isIpAddress) domainRisk += 40;
    if (urlAnalysis?.isSuspiciousTld) domainRisk += 15;
    if (urlAnalysis?.similarToBrand) domainRisk += 25;
    if (whoisResult?.domainAgeScore < 40) domainRisk += 20;
    domainRisk = Math.min(100, domainRisk);

    // Content risk: URL keywords + SSL
    let contentRisk = 0;
    if (urlAnalysis?.hasSuspiciousKeywords) contentRisk += 30;
    if (sslResult?.isValid === false) contentRisk += 30;
    if (urlAnalysis?.hasManySubdomains) contentRisk += 15;
    contentRisk = Math.min(100, contentRisk);

    // Blacklist risk: GSB + VT
    let blacklistRisk = 0;
    if (safeBrowsing?.isSafe === false) blacklistRisk += 60;
    if ((virustotal?.maliciousCount || 0) > 0) blacklistRisk += 40;
    blacklistRisk = Math.min(100, blacklistRisk);

    const total = domainRisk + contentRisk + blacklistRisk || 1;

    // Update legend values
    if (elements.legDomain) elements.legDomain.textContent = `${Math.round(domainRisk)}%`;
    if (elements.legContent) elements.legContent.textContent = `${Math.round(contentRisk)}%`;
    if (elements.legBlacklist) elements.legBlacklist.textContent = `${Math.round(blacklistRisk)}%`;
    if (elements.donutScore) elements.donutScore.textContent = `${riskScore}%`;

    // Draw canvas
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2, cy = H / 2;
    const radius = Math.min(cx, cy) - 6;
    const innerRadius = radius * 0.62;
    ctx.clearRect(0, 0, W, H);

    // Build segments
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const segments = [
        { value: domainRisk, color: isDark ? '#ef4444' : '#dc2626' },      // domain - red
        { value: contentRisk, color: isDark ? '#f59e0b' : '#d97706' },     // content - amber
        { value: blacklistRisk, color: isDark ? '#818cf8' : '#4f46e5' },   // blacklist - indigo
    ];

    // If all zero, show grey safe ring
    const allZero = segments.every(s => s.value === 0);
    if (allZero) {
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.arc(cx, cy, innerRadius, 0, Math.PI * 2, true);
        ctx.fillStyle = isDark ? '#22c55e' : '#16a34a';
        ctx.fill();
        if (elements.donutScore) elements.donutScore.textContent = `${riskScore}%`;
        return;
    }

    let startAngle = -Math.PI / 2;
    segments.forEach((seg, i) => {
        const slice = (seg.value / total) * Math.PI * 2;
        if (slice <= 0) return;

        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(startAngle) * radius, cy + Math.sin(startAngle) * radius);
        ctx.arc(cx, cy, radius, startAngle, startAngle + slice);
        ctx.arc(cx, cy, innerRadius, startAngle + slice, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = seg.color;
        ctx.fill();

        // Gap between segments
        startAngle += slice + 0.025;
    });
}

/** Shared HTML escape helper */
function escapeHtmlStr(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function updateDetailsContent() {
    if (!elements.detailsContent || !state.scanResults) return;
    const { safeBrowsing, virustotal, sslResult, whoisResult, urlAnalysis } = state.scanResults;
    const createCheckItem = (label, status, icon, text, details = '') =>
        `<div class="check-item ${status}"><div class="check-icon"><i class="fas ${icon}"></i></div><div class="check-text"><strong>${escapeHtmlStr(label)}:</strong> ${escapeHtmlStr(text)}${details ? ` <em>${escapeHtmlStr(details)}</em>` : ''}</div></div>`;

    let html = '';
    html += createCheckItem('SSL Certificate', sslResult?.isValid ? 'passed' : 'failed', sslResult?.isValid ? 'fa-lock' : 'fa-lock-open', sslResult?.isValid ? 'Secure (HTTPS)' : 'Insecure or Invalid');
    html += createCheckItem('Google Safe Browsing', safeBrowsing?.isSafe !== false ? 'passed' : 'failed', safeBrowsing?.isSafe !== false ? 'fa-check-circle' : 'fa-exclamation-triangle', safeBrowsing?.isSafe !== false ? 'No threats found' : 'Threats detected!', safeBrowsing?.threats?.join(', '));
    html += createCheckItem('VirusTotal', virustotal?.isSafe ? 'passed' : (virustotal?.maliciousCount > 0 ? 'failed' : 'warning'), 'fa-shield-virus', `${virustotal?.maliciousCount || 0} Malicious, ${virustotal?.suspiciousCount || 0} Suspicious`);
    html += createCheckItem('Domain Age', whoisResult?.domainAgeScore > 60 ? 'passed' : (whoisResult?.domainAgeScore > 20 ? 'warning' : 'failed'), 'fa-calendar-alt', `${whoisResult?.domainAgeString || 'Unknown'}`, `Registered: ${whoisResult?.formatted_create_date || 'N/A'}`);
    if (urlAnalysis?.similarToBrand) {
        html += createCheckItem('Brand Impersonation', 'failed', 'fa-user-secret', `Similar to "${urlAnalysis.similarToBrand}"`, 'Possible typosquatting');
    }
    if (whoisResult?.registrar_name && whoisResult.registrar_name !== 'N/A') {
        html += createCheckItem('Registrar', 'info', 'fa-building', whoisResult.registrar_name);
    }
    elements.detailsContent.innerHTML = html;
}

function updateAlertsSection() {
    if (!elements.alertsCard || !elements.alertsContent) return;
    const { safeBrowsing, virustotal, sslResult, urlAnalysis, whoisResult } = state.scanResults;

    const alerts = [];

    if (safeBrowsing?.isSafe === false && safeBrowsing.threats?.length) {
        safeBrowsing.threats.forEach(t => alerts.push({ type: 'danger', icon: 'fa-triangle-exclamation', title: 'Google Safe Browsing Threat', detail: t }));
    }
    if ((virustotal?.maliciousCount || 0) > 0) {
        alerts.push({ type: 'danger', icon: 'fa-bug', title: 'VirusTotal: Malicious Detections', detail: `${virustotal.maliciousCount} engine(s) flagged this URL` });
    }
    if ((virustotal?.suspiciousCount || 0) > 0) {
        alerts.push({ type: 'warning', icon: 'fa-circle-exclamation', title: 'VirusTotal: Suspicious', detail: `${virustotal.suspiciousCount} engine(s) flagged as suspicious` });
    }
    if (sslResult?.isValid === false) {
        alerts.push({ type: 'warning', icon: 'fa-lock-open', title: 'No HTTPS / SSL', detail: 'Connection is not encrypted — risk of data interception' });
    }
    if (urlAnalysis?.isIpAddress) {
        alerts.push({ type: 'danger', icon: 'fa-server', title: 'IP Address Used as Domain', detail: 'Legitimate sites rarely use bare IP addresses' });
    }
    if (urlAnalysis?.similarToBrand) {
        alerts.push({ type: 'danger', icon: 'fa-user-secret', title: `Brand Impersonation: "${urlAnalysis.similarToBrand}"`, detail: 'Domain may be intentionally mimicking a trusted brand' });
    }
    if (urlAnalysis?.isSuspiciousTld) {
        alerts.push({ type: 'warning', icon: 'fa-globe', title: 'Suspicious Top-Level Domain', detail: 'TLDs like .xyz, .top, .tk are commonly used in phishing' });
    }
    if (urlAnalysis?.hasSuspiciousKeywords) {
        alerts.push({ type: 'warning', icon: 'fa-key', title: 'Suspicious Keywords in URL', detail: 'Phishing URLs often include "login", "verify", "secure", etc.' });
    }
    if (whoisResult && !whoisResult.error && whoisResult.domainAgeScore < 20) {
        alerts.push({ type: 'warning', icon: 'fa-calendar', title: 'Very New Domain', detail: `Domain registered ${whoisResult.domainAgeString} ago — high-risk indicator` });
    }

    if (alerts.length === 0) {
        elements.alertsCard.style.display = 'none';
        return;
    }

    elements.alertsCard.style.display = 'block';
    elements.alertsContent.innerHTML = alerts.map(a => `
        <div class="alert-item ${a.type}">
            <div class="alert-icon"><i class="fas ${a.icon}"></i></div>
            <div class="alert-text">
                <strong>${escapeHtmlStr(a.title)}</strong>
                <span>${escapeHtmlStr(a.detail)}</span>
            </div>
        </div>
    `).join('');
}

function updateReportContent() {
    if (!elements.reportContent || !state.scanResults) return;
    const { url, riskScore, safeBrowsing, virustotal, whoisResult, urlAnalysis } = state.scanResults;
    const escapeHtml = (unsafe) => String(unsafe).replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const addLine = (label, value) => value !== undefined && value !== null && value !== 'N/A' ? `<div><strong>${label}:</strong> ${escapeHtml(String(value))}</div>` : '';

    let html = `<div class="report-item"><strong>URL:</strong> <span style="word-break:break-all;">${escapeHtml(url)}</span></div>`;
    html += `<div class="report-item"><strong>Risk Score:</strong> ${riskScore}%</div>`;
    html += `<div class="report-item"><strong>Google Safe Browsing:</strong> ${safeBrowsing?.isSafe ? 'Clean' : `Threats: ${escapeHtml(safeBrowsing?.threats?.join(', '))}`} ${safeBrowsing?.error ? `<span class="error-text">(${escapeHtml(safeBrowsing.error)})</span>` : ''}</div>`;
    html += `<div class="report-item"><strong>VirusTotal:</strong> ${virustotal?.maliciousCount || 0} Malicious, ${virustotal?.suspiciousCount || 0} Suspicious ${virustotal?.error ? `<span class="error-text">(${escapeHtml(virustotal.error)})</span>` : ''}</div>`;
    html += `<div class="report-item"><strong>URL Structure Analysis</strong>
        ${addLine('Uses IP Address', urlAnalysis?.isIpAddress ? 'Yes' : 'No')}
        ${addLine('Suspicious TLD', urlAnalysis?.isSuspiciousTld ? 'Yes' : 'No')}
        ${addLine('Suspicious Keywords', urlAnalysis?.hasSuspiciousKeywords ? 'Yes' : 'No')}
        ${addLine('Brand Impersonation', urlAnalysis?.similarToBrand || 'None detected')}
    </div>`;
    html += `<div class="report-item"><strong>Domain Info (WHOIS)</strong>
        ${addLine('Registered', whoisResult?.formatted_create_date)}
        ${addLine('Age', whoisResult?.domainAgeString)}
        ${addLine('Registrar', whoisResult?.registrar_name)}
        ${whoisResult?.error ? `<span class="error-text">(${escapeHtml(whoisResult.error)})</span>` : ''}
    </div>`;
    elements.reportContent.innerHTML = html;
}

/**
 * Parse the structured AI response into styled HTML.
 * Expected format: headings like "Impersonation Risk:", "Top Signals:", "Risk Score:", "Verdict:", "Confidence:"
 */
function formatAIResponse(text) {
    if (!text) return '<p class="placeholder-text">No analysis available.</p>';

    const safe = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const lines = safe.split('\n').filter(l => l.trim());
    let html = '';

    // Highlight keywords
    const highlight = (str) => str
        .replace(/(high risk|phishing|dangerous|malicious|suspicious|flagged|typosquat|impersonat)/gi, '<span class="highlight">$1</span>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Normalize a line to check if it starts a known section
    const normalizeKey = (line) => line
        .replace(/\*\*/g, '')
        .replace(/^#+\s*/, '')
        .replace(/[:\-*•]+$/, '')
        .toLowerCase().trim();

    const headings = {
        'impersonation risk': null,
        'top signals': null,
        'risk score': null,
        'verdict': null,
        'confidence': null,
    };

    let currentSection = null;
    let sectionData = {};

    for (const line of lines) {
        const normed = normalizeKey(line);
        const matchedKey = Object.keys(headings).find(k => normed === k || normed.startsWith(k));

        if (matchedKey) {
            currentSection = matchedKey;
            sectionData[matchedKey] = [];
        } else if (currentSection) {
            const clean = line.replace(/^[-•*\d]+\.?\s*/, '').trim();
            if (clean) sectionData[currentSection].push(clean);
        }
    }

    // Render each section
    if (sectionData['impersonation risk']?.length) {
        const risk = sectionData['impersonation risk'][0];
        const riskLevel = /high/i.test(risk) ? 'danger' : /medium/i.test(risk) ? 'warning' : 'safe';
        html += `<h3>🎭 Impersonation Risk</h3>`;
        html += `<div class="alert-item ${riskLevel}" style="margin-bottom:8px;"><div class="alert-icon"><i class="fas fa-user-secret"></i></div><div class="alert-text"><span>${highlight(risk)}</span></div></div>`;
    }

    if (sectionData['top signals']?.length) {
        html += `<h3>🔍 Top Signals</h3><ul>`;
        sectionData['top signals'].slice(0, 3).forEach(s => {
            html += `<li>${highlight(s)}</li>`;
        });
        html += `</ul>`;
    }

    if (sectionData['verdict']?.length) {
        const v = sectionData['verdict'][0].toUpperCase();
        const cls = v.includes('PHISHING') ? 'phishing' : v.includes('SUSPICIOUS') ? 'suspicious' : 'safe';
        const icon = cls === 'phishing' ? 'fa-skull' : cls === 'suspicious' ? 'fa-triangle-exclamation' : 'fa-circle-check';
        html += `<h3>⚖️ Verdict</h3>`;
        html += `<span class="verdict-badge ${cls}"><i class="fas ${icon}"></i>${sectionData['verdict'][0]}</span>`;
        if (sectionData['verdict'].length > 1) {
            html += `<p style="font-size:11.5px;color:var(--text-secondary);margin-top:4px;">${highlight(sectionData['verdict'].slice(1).join(' '))}</p>`;
        }
    }

    if (sectionData['risk score']?.length) {
        html += `<h3>📊 AI Risk Score</h3>`;
        html += `<p style="font-size:13px;font-weight:700;color:var(--text-primary);">${sectionData['risk score'][0]}</p>`;
    }

    if (sectionData['confidence']?.length) {
        html += `<span class="confidence-tag">Confidence: ${sectionData['confidence'][0]}</span>`;
    }

    return html || `<pre style="font-size:11.5px;white-space:pre-wrap;color:var(--text-secondary);">${safe}</pre>`;
}

function updateIntentContent() {
    if (!elements.intentContent || !state.scanResults?.intentAnalysis) return;
    const { text, error } = state.scanResults.intentAnalysis;
    if (error) {
        elements.intentContent.innerHTML = `<p class="api-key-notice"><i class="fas fa-key"></i> ${error}</p>`;
    } else {
        elements.intentContent.innerHTML = formatAIResponse(text);
    }
}

// --- Phishing Warning Overlay ---
function showPhishingOverlay(score, url) {
    if (!elements.phishingWarningOverlay) return;
    if (elements.overlayDomainText) elements.overlayDomainText.textContent = extractDomainFromUrl(url) || url;
    if (elements.overlayRiskScore) elements.overlayRiskScore.textContent = `${score}%`;
    elements.phishingWarningOverlay.style.display = 'block';
}

function hidePhishingOverlay() {
    if (elements.phishingWarningOverlay) elements.phishingWarningOverlay.style.display = 'none';
}

// --- UI & State Management ---
function resetUI() {
    if (elements.mainContent) elements.mainContent.style.display = 'none';
    if (elements.actionsBar) elements.actionsBar.style.display = 'none';
    showLoading(false);
    window.updateProgressCircle(elements.overallScoreProgress, 0, 'var(--neutral-color)');
    if (elements.overallScoreText) elements.overallScoreText.innerHTML = `?<span>%</span>`;
    if (elements.riskIndicatorBar) elements.riskIndicatorBar.style.setProperty('--position', '0');
    if (elements.riskPill) { elements.riskPill.textContent = 'Unknown'; elements.riskPill.className = 'risk-pill'; }
    updateStatusBadge('ready');
    if (elements.alertsCard) elements.alertsCard.style.display = 'none';
    if (window.phishGuardWhois) window.phishGuardWhois.resetUI();
    elements.lastScan.textContent = 'Never';
    elements.scanTime.textContent = '0s';
    clearError();
}

function resetUIForScan() {
    elements.mainContent.style.display = 'none';
    if (elements.actionsBar) elements.actionsBar.style.display = 'none';
    clearError();
}

function toggleSection(contentElement, buttonElement) {
    if (!contentElement || !buttonElement) return;
    const isExpanded = buttonElement.getAttribute('aria-expanded') === 'true';
    buttonElement.setAttribute('aria-expanded', !isExpanded);
    contentElement.setAttribute('aria-hidden', isExpanded);
}

function showLoading(show, message = 'Analyzing…') {
    if (!elements.loading) return;
    elements.loading.style.display = show ? 'flex' : 'none';
    if (show && elements.loadingMessage) elements.loadingMessage.textContent = message;
    if (elements.checkBtn) elements.checkBtn.disabled = show;
    if (elements.currentTabBtn) elements.currentTabBtn.disabled = show;
}

function updateProgress(step, message) {
    if (elements.loading?.style.display === 'none') return;
    const percentage = Math.min(100, (step / CONFIG.SCAN_STEPS) * 100);
    if (elements.progressFill) elements.progressFill.style.width = `${percentage}%`;
    if (elements.loadingMessage) elements.loadingMessage.textContent = message;
}

function showError(message) {
    if (!elements.errorDisplay) return;
    clearTimeout(state.errorTimeoutId);
    elements.errorDisplay.textContent = message;
    elements.errorDisplay.style.display = 'block';
    state.errorTimeoutId = setTimeout(() => { elements.errorDisplay.style.display = 'none'; }, CONFIG.ERROR_DISPLAY_DURATION);
}

function clearError() {
    clearTimeout(state.errorTimeoutId);
    if (elements.errorDisplay) elements.errorDisplay.style.display = 'none';
}

// --- Theme ---
async function toggleTheme() {
    const theme = elements.themeSwitch.checked ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    await chrome.storage.local.set({ theme });
    // Redraw chart in new theme colors
    if (state.scanResults) updateDonutChart();
}

async function loadSettings() {
    const { theme = 'light' } = await chrome.storage.local.get('theme');
    if (elements.themeSwitch) elements.themeSwitch.checked = (theme === 'dark');
    document.documentElement.setAttribute('data-theme', theme);
}

// --- History ---
async function loadHistory() {
    const { history = [] } = await chrome.storage.local.get('history');
    state.history = history;
}

async function addToHistory(result) {
    const existingIndex = state.history.findIndex(item => item.url === result.url);
    if (existingIndex > -1) state.history.splice(existingIndex, 1);
    state.history.unshift(result);
    if (state.history.length > CONFIG.MAX_HISTORY_ITEMS) state.history.length = CONFIG.MAX_HISTORY_ITEMS;
    await chrome.storage.local.set({ history: state.history });
}

function showHistoryModal() {
    const overlay = document.createElement('div');
    overlay.className = 'phishguard-modal-overlay';
    const content = document.createElement('div');
    content.className = 'phishguard-modal-content';
    overlay.appendChild(content);

    content.innerHTML = `
        <h2>Scan History</h2>
        <div class="phishguard-history-list">
            ${state.history.length === 0 ? '<p style="text-align:center;color:var(--text-muted);font-size:12px;padding:12px 0;">No history yet.</p>' : ''}
        </div>
        <button class="close-btn">Close</button>
    `;

    const list = content.querySelector('.phishguard-history-list');
    state.history.forEach(item => {
        const itemEl = document.createElement('div');
        itemEl.className = 'phishguard-history-item';
        itemEl.dataset.url = item.url;
        const riskLevel = item.riskScore > 70 ? 'danger' : item.riskScore > 40 ? 'warning' : 'safe';
        itemEl.innerHTML = `
            <span class="history-url" title="${item.url}">${item.url}</span>
            <span class="history-score score-${riskLevel}">${item.riskScore}%</span>
        `;
        itemEl.addEventListener('click', () => {
            elements.urlInput.value = item.url;
            handleCheckUrl();
            document.body.removeChild(overlay);
        });
        list.appendChild(itemEl);
    });

    const close = () => document.body.removeChild(overlay);
    content.querySelector('.close-btn').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    document.body.appendChild(overlay);
}

// --- Cache ---
async function getFromCache(url) {
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');
    const cachedItem = scanCache[url];
    if (cachedItem && (Date.now() - cachedItem.timestamp < CONFIG.CACHE_DURATION)) return cachedItem;
    return null;
}

async function saveToCache(url, data) {
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');
    scanCache[url] = data;
    await chrome.storage.local.set({ scanCache });
}

async function loadLastScan() {
    const { lastScan } = await chrome.storage.local.get('lastScan');
    if (lastScan?.url && lastScan.riskScore !== undefined) {
        state.scanResults = lastScan;
        elements.urlInput.value = lastScan.url;
        if (window.phishGuardWhois) window.phishGuardWhois.updateDomainAgeMetricUI(lastScan.whoisResult);
        updateUI(false);
    } else {
        resetUI();
    }
}

// --- Utility Functions ---
function isValidUrl(url) {
    if (!url?.trim()) return { valid: false, message: 'URL is empty.' };
    let finalUrl = url.trim();
    if (!/^[a-zA-Z]+:\/\//.test(finalUrl)) finalUrl = `https://${finalUrl}`;
    try {
        const parsed = new URL(finalUrl);
        if (!['http:', 'https:'].includes(parsed.protocol)) return { valid: false, message: 'Unsupported protocol (must be http or https).' };
        if (!parsed.hostname || !parsed.hostname.includes('.')) return { valid: false, message: 'Invalid hostname.' };
        return { valid: true, url: finalUrl };
    } catch {
        return { valid: false, message: 'Invalid URL format.' };
    }
}

function extractDomainFromUrl(url) {
    try {
        const hostname = new URL(url).hostname;
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;
        return hostname.replace(/^www\./, '');
    } catch { return null; }
}

function formatDate(timestamp, includeTime = false) {
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Invalid Date';
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        if (includeTime) { options.hour = 'numeric'; options.minute = '2-digit'; }
        return date.toLocaleString(undefined, options);
    } catch { return 'Date Error'; }
}