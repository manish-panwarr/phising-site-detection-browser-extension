/**
 * popup.js - Main logic for the PhishGuard extension popup.
 * This script orchestrates the entire analysis process, including:
 * - Handling user interactions (button clicks, input).
 * - Fetching data from various APIs (Google, VirusTotal, Whoxy, OpenAI/OpenRouter).
 * - Calculating a comprehensive risk score.
 * - Dynamically updating the UI with results and animations.
 * - Managing local cache and history.
 *
 * NOTE: This script has a dependency on another script that must define the `window.phishGuardWhois` object.
 * This object is expected to have the methods `fetchAndDisplayDomainAge`, `updateDomainAgeMetricUI`, and `resetUI`.
 */

// --- Global Helper ---
/**
 * Updates the visual properties of a CSS conic-gradient progress circle.
 * @param {HTMLElement} element - The progress circle container element.
 * @param {number} percent - The percentage (0-100) to fill the circle.
 * @param {string} [color] - Optional CSS color value for the progress arc.
 */
window.updateProgressCircle = (element, percent, color) => {
    if (!element) return;
    const clampedPercent = Math.min(100, Math.max(0, percent));
    element.style.setProperty('--progress', `${clampedPercent}`);
    if (color) element.style.setProperty('--color', color);
};

// --- Configuration & State ---
const CONFIG = {
    CACHE_DURATION: 5 * 60 * 1000, // 5 minutes for runtime cache
    SCAN_STEPS: 8, // Total steps for the progress bar
    MAX_HISTORY_ITEMS: 20,
    ERROR_DISPLAY_DURATION: 7000,
};

const state = {
    currentUrl: '',
    currentTabTitle: '',
    scanResults: null,
    apiStatus: 'ready', // 'ready', 'loading', 'error'
    history: [],
    errorTimeoutId: null,
};

// --- DOM Element Cache ---
const elements = {};
function cacheElements() {
    const ids = [
        'body', 'url-input', 'check-btn', 'current-tab-btn', 'history-btn', 'settings-btn',
        'loading', 'loading-message', 'progress-fill', 'main-content',
        'overall-score-progress', 'overall-score-text', 'summary-title', 'summary-text',
        'risk-indicator', 'https-progress', 'https-score', 'https-text',
        'structure-progress', 'structure-score', 'structure-text',
        'reputation-progress', 'reputation-score', 'reputation-text',
        'details-content', 'report-content', 'intent-content',
        'toggle-details', 'toggle-report', 'toggle-intent',
        'last-scan', 'scan-time', 'theme-switch', 'error-display'
    ];
    ids.forEach(id => {
        const camelCaseId = id.replace(/-(\w)/g, (_, c) => c.toUpperCase());
        elements[camelCaseId] = document.getElementById(id);
    });
    // Add elements that don't follow the standard ID pattern
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
    elements.themeSwitch?.addEventListener('change', toggleTheme);
}


// --- Event Handlers ---

/** Initiates a scan based on the URL in the input field. */
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

/** Initiates a scan using the URL of the currently active browser tab. */
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

/** Opens the extension's options page. */
function openOptionsPage() {
    chrome.runtime.openOptionsPage?.();
}


// --- Core Scan Logic ---

/**
 * The main function that orchestrates the entire website analysis process.
 * @param {string} url - The URL to be scanned.
 */
async function scanWebsite(url) {
    if (state.apiStatus === 'loading') return;
    const scanStartTime = Date.now();
    state.apiStatus = 'loading';
    showLoading(true, 'Initiating analysis...');
    clearError();
    resetUIForScan();

    try {
        updateProgress(1, 'Validating URL...');
        const domain = extractDomainFromUrl(url);
        if (!domain) throw new Error("Could not extract a valid domain.");

        updateProgress(2, 'Checking cache...');
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

        updateProgress(3, 'Fetching API keys...');
        const apiKeys = await chrome.storage.local.get(['googleApiKey', 'virustotalApiKey', 'whoxyApiKey', 'chatGptApiKey']);

        updateProgress(4, 'Checking Google Safe Browsing...');
        const safeBrowsingPromise = apiKeys.googleApiKey ? checkGoogleSafeBrowsing(url, apiKeys.googleApiKey) : Promise.resolve({ error: 'API key missing' });

        updateProgress(5, 'Querying VirusTotal...');
        const virustotalPromise = apiKeys.virustotalApiKey ? checkVirusTotal(url, apiKeys.virustotalApiKey) : Promise.resolve({ error: 'API key missing' });

        updateProgress(6, 'Analyzing URL & SSL...');
        const sslPromise = checkSslCertificate(url);
        const urlAnalysisResult = analyzeUrlStructure(url);

        const [safeBrowsingResult, virustotalResult, sslResult] = await Promise.all([safeBrowsingPromise, virustotalPromise, sslPromise]);

        updateProgress(7, 'Fetching domain info (WHOIS)...');
        let whoisResult = { error: 'WHOIS module not loaded' };
        if (window.phishGuardWhois) {
            whoisResult = await window.phishGuardWhois.fetchAndDisplayDomainAge(domain, apiKeys.whoxyApiKey);
        } else {
             console.error("PhishGuard: window.phishGuardWhois is not defined. WHOIS check skipped.");
        }

        let preliminaryResults = { url, safeBrowsing: safeBrowsingResult, virustotal: virustotalResult, whoisResult, sslResult, urlAnalysis: urlAnalysisResult };

        updateProgress(8, 'Analyzing intent with AI...');
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
        gsbStatus: safeBrowsing?.isSafe ? 'Safe' : `Threats found: ${get(safeBrowsing.threats?.join(', '), 'Unknown')}`,
        urlKeywords: urlAnalysis?.hasSuspiciousKeywords ? 'Yes' : 'No',
        urlSuspiciousTld: urlAnalysis?.isSuspiciousTld ? 'Yes' : 'No',
        similarToBrand: get(urlAnalysis?.similarToBrand, 'Unknown'),
        fullUrl: get(url)
    };

    return `
Analyze the phishing risk of the following website strictly based on metadata only. Do not access or assume the actual content.

Focus especially on spelling similarity with top global companies (e.g. Amazon, Google, Microsoft, SBI, PayPal, etc.), domain manipulation, and impersonation signs. Be very strict in evaluating spelling variations.

Website URL: ${promptData.fullUrl}
--- METADATA ---
- Google Safe Browsing: ${promptData.gsbStatus}
- VirusTotal Detections: ${promptData.vtDetections}
- Domain Age: ${promptData.whoisAge} (Registered on: ${promptData.whoisRegistered})
- Secure Connection (SSL): ${promptData.sslValid}
- Suspicious Keywords in URL: ${promptData.urlKeywords}
- Suspicious TLD (like .xyz, .top): ${promptData.urlSuspiciousTld}
- Similar to known brand: ${promptData.similarToBrand}
--- END METADATA ---

Give a clear, short, structured risk summary under these headings:
Impersonation Risk:
- Describe if it resembles a known brand very closely, moderately, or not at all.

Key Red Flags:
- List 2 or 3 specific metadata issues that suggest risk.

Overall Verdict:
- Give one clear sentence that summarizes phishing risk.
`.trim();
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
                temperature: 0.3,
                max_tokens: 250
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
        if (urlObj.protocol === 'http:') return { isValid: false, error: 'Site uses insecure HTTP' };
        return { isValid: null, error: `Unsupported protocol: ${urlObj.protocol}` };
    } catch {
        return { isValid: false, error: 'Invalid URL for SSL check' };
    }
}

function analyzeUrlStructure(url) {
    try {
        const urlObj = new URL(url);
        const suspiciousTlds = ['.xyz', '.top', '.info', '.loan', '.buzz', '.tk', '.biz', '.win', '.link'];
        const suspiciousKeywords = ['login', 'signin', 'verify', 'account', 'update', 'secure', 'confirm', 'support', 'password', 'bank'];
        return {
            isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
            isSuspiciousTld: suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld)),
            hasManySubdomains: (urlObj.hostname.match(/\./g) || []).length > 2,
            hasSuspiciousKeywords: suspiciousKeywords.some(kw => url.toLowerCase().includes(kw)),
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
    if (whoisResult && whoisResult.domainAgeScore < 40) score += 15;
    else if (whoisResult && whoisResult.domainAgeScore < 80) score += 5;

    if (safeBrowsing?.isSafe && virustotal?.isSafe && sslResult?.isValid && whoisResult && whoisResult.domainAgeScore > 80) score -= 10;

    return Math.min(100, Math.max(0, Math.round(score)));
}


// --- UI Update Functions ---

/** Master function to update the entire UI based on scan results. */
async function updateUI(saveHistory = true) {
    if (!state.scanResults) return resetUI();
    const { riskScore, timestamp, scanTime } = state.scanResults;
    const riskLevel = riskScore > 70 ? 'danger' : riskScore > 40 ? 'warning' : 'safe';
    const riskText = riskLevel === 'danger' ? 'High Risk' : riskLevel === 'warning' ? 'Potential Risk' : 'Likely Safe';
    const scoreColor = `var(--${riskLevel}-color)`;

    elements.summaryTitle.textContent = riskText;
    elements.summaryTitle.className = `summary-title ${riskLevel}`;
    elements.summaryText.textContent = generateSummaryText(state.scanResults);
    window.updateProgressCircle(elements.overallScoreProgress, riskScore, scoreColor);
    elements.overallScoreText.innerHTML = `${riskScore}<span>%</span>`;
    if (elements.riskIndicatorBar) elements.riskIndicatorBar.style.setProperty('--position', `${riskScore}`);

    updateAllMetrics();
    updateDetailsContent();
    updateReportContent();
    updateIntentContent();

    elements.lastScan.textContent = formatDate(timestamp, true);
    elements.scanTime.textContent = `${(scanTime || 0).toFixed(1)}s`;
    elements.mainContent.style.display = 'block';

    if (saveHistory) {
      await addToHistory(state.scanResults);
    }
    chrome.storage.local.set({ lastScan: state.scanResults }).catch(console.error);
}

function updateAllMetrics() {
    const { sslResult, urlAnalysis, safeBrowsing, virustotal } = state.scanResults;

    let httpsScore = sslResult?.isValid ? 100 : sslResult?.isValid === false ? 0 : 25;
    window.updateProgressCircle(elements.httpsProgress, httpsScore, httpsScore === 100 ? 'var(--safe-color)' : httpsScore === 0 ? 'var(--danger-color)' : 'var(--warning-color)');
    elements.httpsScore.innerHTML = httpsScore === 100 ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>';
    elements.httpsText.textContent = httpsScore === 100 ? 'Secure' : 'Insecure';

    let structureScore = urlAnalysis ? 100 - Object.values(urlAnalysis).filter(v => v === true).length * 25 : 50;
    structureScore = Math.max(0, structureScore);
    window.updateProgressCircle(elements.structureProgress, structureScore, structureScore > 75 ? 'var(--safe-color)' : structureScore > 40 ? 'var(--warning-color)' : 'var(--danger-color)');
    elements.structureScore.innerHTML = `${structureScore}<span>%</span>`;

    let repScore = 100 - (safeBrowsing?.isSafe === false ? 60 : 0) - (virustotal?.maliciousCount * 10) - (virustotal?.suspiciousCount * 5);
    repScore = Math.max(0, repScore);
    window.updateProgressCircle(elements.reputationProgress, repScore, repScore > 80 ? 'var(--safe-color)' : repScore > 40 ? 'var(--warning-color)' : 'var(--danger-color)');
    elements.reputationScore.innerHTML = `${repScore}<span>%</span>`;
}

function updateDetailsContent() {
    if (!elements.detailsContent || !state.scanResults) return;
    const { safeBrowsing, virustotal, sslResult, whoisResult } = state.scanResults;
    const createCheckItem = (label, status, icon, text, details = '') =>
        `<div class="check-item ${status}"><div class="check-icon"><i class="fas ${icon}"></i></div><div class="check-text"><strong>${label}:</strong> ${text}${details ? ` <em>(${details})</em>` : ''}</div></div>`;

    let html = '';
    html += createCheckItem('SSL Certificate', sslResult?.isValid ? 'passed' : 'failed', sslResult?.isValid ? 'fa-lock' : 'fa-lock-open', sslResult?.isValid ? 'Secure (HTTPS)' : 'Insecure or Invalid');
    html += createCheckItem('Google Safe Browsing', safeBrowsing?.isSafe ? 'passed' : 'failed', safeBrowsing?.isSafe ? 'fa-check-circle' : 'fa-exclamation-triangle', safeBrowsing?.isSafe ? 'No threats found' : `Threats detected!`, safeBrowsing.threats?.join(', '));
    html += createCheckItem('VirusTotal', virustotal?.isSafe ? 'passed' : (virustotal?.maliciousCount > 0 ? 'failed' : 'warning'), 'fa-shield-virus', `${virustotal?.maliciousCount || 0} Malicious, ${virustotal?.suspiciousCount || 0} Suspicious`);
    html += createCheckItem('Domain Age', whoisResult?.domainAgeScore > 60 ? 'passed' : (whoisResult?.domainAgeScore > 20 ? 'warning' : 'failed'), 'fa-calendar-alt', `${whoisResult?.domainAgeString || 'Unknown'}`, `Registered: ${whoisResult?.formatted_create_date || 'N/A'}`);
    elements.detailsContent.innerHTML = html;
}

function updateReportContent() {
    if (!elements.reportContent || !state.scanResults) return;
    const { url, riskScore, safeBrowsing, virustotal, whoisResult, urlAnalysis } = state.scanResults;
    const escapeHtml = (unsafe) => String(unsafe).replace(/</g, "<").replace(/>/g, ">");
    const addLine = (label, value) => value !== undefined && value !== null && value !== 'N/A' ? `<div><strong>${label}:</strong> ${escapeHtml(value)}</div>` : '';

    let html = `<div class="report-item"><strong>URL:</strong> <span style="word-break: break-all;">${escapeHtml(url)}</span></div>`;
    html += `<div class="report-item"><strong>Risk Score:</strong> ${riskScore}%</div>`;
    html += `<div class="report-item"><strong>Google Safe Browsing:</strong> ${safeBrowsing?.isSafe ? 'Clean' : `Threats: ${escapeHtml(safeBrowsing.threats?.join(', '))}`} ${safeBrowsing.error ? `<span class="error-text">(${escapeHtml(safeBrowsing.error)})</span>` : ''}</div>`;
    html += `<div class="report-item"><strong>VirusTotal:</strong> ${virustotal?.maliciousCount || 0} Malicious, ${virustotal?.suspiciousCount || 0} Suspicious ${virustotal.error ? `<span class="error-text">(${escapeHtml(virustotal.error)})</span>` : ''}</div>`;
    html += `<div class="report-item"><strong>URL Structure Analysis</strong>
        ${addLine('Uses IP Address', urlAnalysis.isIpAddress ? 'Yes' : 'No')}
        ${addLine('Suspicious TLD', urlAnalysis.isSuspiciousTld ? 'Yes' : 'No')}
        ${addLine('Suspicious Keywords', urlAnalysis.hasSuspiciousKeywords ? 'Yes' : 'No')}
    </div>`;
    html += `<div class="report-item"><strong>Domain Info (WHOIS)</strong>
        ${addLine('Registered', whoisResult?.formatted_create_date)}
        ${addLine('Age', whoisResult?.domainAgeString)}
        ${addLine('Registrar', whoisResult?.registrar_name)}
        ${whoisResult?.error ? `<span class="error-text">(${escapeHtml(whoisResult.error)})</span>` : ''}
    </div>`;
    elements.reportContent.innerHTML = html;
}

// NEW: Function to parse AI response into styled HTML
function formatAIResponse(text) {
    if (!text) return '<p>No analysis available.</p>';

    // Sanitize the whole text first to prevent any HTML injection from the AI
    let sanitizedText = text.replace(/</g, "<").replace(/>/g, ">");

    // General keywords and patterns to highlight
    const highlightPatterns = [
        /(\d+ malicious)/ig,
        /(\d+ suspicious)/ig,
        /(high risk|moderate risk|potential risk|major red flags)/ig,
        /(proceed with caution|avoid clicking|not recommended)/ig,
        /(phishing attempt|deceive users|impersonate)/ig,
        /(suspicious tld|suspicious domain)/ig,
        /(very new|recently registered|lack of history)/ig,
        /(\.\w{3,})/g, // Highlight TLDs like .buzz, .info, but not .co, .io
        /(Error)/ig
    ];

    let html = sanitizedText;
    for (const pattern of highlightPatterns) {
        html = html.replace(pattern, '<span class="highlight">$1</span>');
    }

    // Build the final HTML line by line for structure (headings, lists)
    const lines = html.split('\n').filter(line => line.trim() !== '');
    let finalHtml = '';
    let inList = false;

    for (const line of lines) {
        // Check for headings like **Impersonation Risk:**
        if (line.startsWith('**') && line.includes(':**')) {
            if (inList) {
                finalHtml += '</ul>'; // Close previous list if a new heading starts
                inList = false;
            }
            finalHtml += line.replace(/\*\*(.*?):\*\*/, '<h3>$1:</h3>');
            // If the heading is for the list, start a new <ul>
            if (line.toLowerCase().includes('key red flags')) {
                finalHtml += '<ul>';
                inList = true;
            }
        }
        // Check for numbered list items like "1. ..."
        else if (inList && line.match(/^\s*\d+\.\s*/)) {
            finalHtml += `<li>${line.replace(/^\s*\d+\.\s*/, '')}</li>`;
        }
        // Otherwise, it's a regular paragraph
        else {
             if (inList) { // A paragraph after a list means the list has ended
                finalHtml += '</ul>';
                inList = false;
             }
            finalHtml += `<p>${line}</p>`;
        }
    }

    if (inList) {
        finalHtml += '</ul>'; // Ensure any open list is closed at the end
    }

    return finalHtml;
}

// UPDATED: This function now uses the new formatter
function updateIntentContent() {
    if (!elements.intentContent || !state.scanResults?.intentAnalysis) return;
    const { text, error } = state.scanResults.intentAnalysis;
    if (error) {
        elements.intentContent.innerHTML = `<p class="api-key-notice">${error}</p>`;
    } else {
        // Use the new formatter to convert the AI's text to styled HTML
        elements.intentContent.innerHTML = formatAIResponse(text);
    }
}


// --- UI & State Management ---

function resetUI() {
    if (elements.mainContent) elements.mainContent.style.display = 'none';
    showLoading(false);
    elements.summaryTitle.textContent = 'Website Safety';
    elements.summaryTitle.className = 'summary-title';
    elements.summaryText.textContent = "Enter a URL or use 'Current Tab' to start.";
    window.updateProgressCircle(elements.overallScoreProgress, 0, 'var(--neutral-color)');
    elements.overallScoreText.innerHTML = `?<span>%</span>`;
    if (elements.riskIndicatorBar) elements.riskIndicatorBar.style.setProperty('--position', '0');

    updateMetric('https', 0, '?');
    updateMetric('structure', 0, '?<span>%</span>');
    updateMetric('reputation', 0, '?<span>%</span>');
    if (window.phishGuardWhois) {
      window.phishGuardWhois.resetUI();
    }

    [elements.detailsContent, elements.reportContent, elements.intentContent].forEach((el, i) => {
        const btn = [elements.toggleDetails, elements.toggleReport, elements.toggleIntent][i];
        if (el && btn) {
            const isExpanded = i === 0;
            el.setAttribute('aria-hidden', !isExpanded);
            btn.setAttribute('aria-expanded', isExpanded);
        }
    });

    elements.lastScan.textContent = 'Never';
    elements.scanTime.textContent = '0s';
    clearError();
}

function resetUIForScan() {
    elements.mainContent.style.display = 'none';
    clearError();
}

function toggleSection(contentElement, buttonElement) {
    if (!contentElement || !buttonElement) return;
    const isExpanded = buttonElement.getAttribute('aria-expanded') === 'true';
    buttonElement.setAttribute('aria-expanded', !isExpanded);
    contentElement.setAttribute('aria-hidden', isExpanded);
}

function generateSummaryText(results) {
    const { riskScore, whoisResult, virustotal } = results;
    if (riskScore > 70) return `This site has major red flags. The domain is ${whoisResult?.domainAgeString || 'very new'}, and ${virustotal?.maliciousCount || 'several'} engines flagged it as malicious.`;
    if (riskScore > 40) return `Caution is advised. While not definitively malicious, this site has some suspicious properties like its age or URL structure.`;
    return 'Analysis complete. This website appears to be safe, with no major threats detected from our scans.';
}

function showLoading(show, message = 'Analyzing...') {
    if (!elements.loading) return;
    elements.loading.style.display = show ? 'flex' : 'none';
    if (show) elements.loadingMessage.textContent = message;
    elements.checkBtn.disabled = show;
    elements.currentTabBtn.disabled = show;
}

function updateProgress(step, message) {
    if (elements.loading.style.display === 'none') return;
    const percentage = Math.min(100, (step / CONFIG.SCAN_STEPS) * 100);
    elements.progressFill.style.width = `${percentage}%`;
    elements.loadingMessage.textContent = message;
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
    if(elements.errorDisplay) elements.errorDisplay.style.display = 'none';
}

function updateMetric(prefix, score, text) {
    const progressEl = elements[`${prefix}Progress`];
    const scoreEl = elements[`${prefix}Score`];
    if(progressEl) window.updateProgressCircle(progressEl, score || 0, 'var(--neutral-color)');
    if(scoreEl) scoreEl.innerHTML = text;
}


// --- Theme, History, and Cache ---

async function toggleTheme() {
    const theme = elements.themeSwitch.checked ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    await chrome.storage.local.set({ theme });
}

async function loadSettings() {
    const { theme = 'light' } = await chrome.storage.local.get('theme');
    if (elements.themeSwitch) {
        elements.themeSwitch.checked = (theme === 'dark');
    }
    document.documentElement.setAttribute('data-theme', theme);
}

async function loadHistory() {
    const { history = [] } = await chrome.storage.local.get('history');
    state.history = history;
}

async function addToHistory(result) {
    const existingIndex = state.history.findIndex(item => item.url === result.url);
    if (existingIndex > -1) {
      state.history.splice(existingIndex, 1);
    }
    state.history.unshift(result);
    if (state.history.length > CONFIG.MAX_HISTORY_ITEMS) {
        state.history.length = CONFIG.MAX_HISTORY_ITEMS;
    }
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
            ${state.history.length === 0 ? '<p style="text-align: center; color: var(--text-light);">No history yet.</p>' : ''}
        </div>
        <button class="action-btn close-btn">Close</button>
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
    overlay.addEventListener('click', (e) => { if(e.target === overlay) close(); });

    document.body.appendChild(overlay);
}

async function getFromCache(url) {
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');
    const cachedItem = scanCache[url];
    if (cachedItem && (Date.now() - cachedItem.timestamp < CONFIG.CACHE_DURATION)) {
        return cachedItem;
    }
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
        if (window.phishGuardWhois) {
            window.phishGuardWhois.updateDomainAgeMetricUI(lastScan.whoisResult);
        }
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