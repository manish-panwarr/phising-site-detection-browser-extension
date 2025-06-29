// whois.js - Handles WHOIS data fetching, processing, and updates the Domain Age metric UI.
// It exposes functions for popup.js to use for fetching and displaying domain data.

window.phishGuardWhois = (function() {
    'use strict';

    // --- Module-specific Elements Cache ---
    let elements = {};

    /**
     * Caches DOM elements used by this module to avoid repeated queries.
     */
    function cacheElements() {
        elements = {
            domainAgeProgress: document.getElementById('domain-age-progress'),
            domainAgeTextDisplay: document.getElementById('domain-age-text-display'),
            domainAgeTextLabel: document.getElementById('domain-age-text-label'),
        };
        if (!elements.domainAgeProgress || !elements.domainAgeTextDisplay || !elements.domainAgeTextLabel) {
            console.error("PhishGuard WHOIS: Failed to cache essential UI elements for Domain Age.");
        }
    }

    /**
     * Fetches WHOIS data from the Whoxy API for a given domain.
     * @param {string} domain - The domain name to query.
     * @param {string} apiKey - The Whoxy API key.
     * @returns {Promise<object>} - A promise resolving to the API response or a standardized error object.
     */
    async function fetchWhoisData(domain, apiKey) {
        if (!domain) return { error: "No domain provided", status: 0 };
        if (!apiKey) return { error: "WHOIS API Key missing", status: 0 };

        const apiUrl = `https://api.whoxy.com/?key=${apiKey}&whois=${domain}`;

        try {
            const response = await fetch(apiUrl);
            if (!response.ok) {
                return { error: `WHOIS API HTTP Error ${response.status}`, status: 0 };
            }
            const data = await response.json();
            if (data.status !== 1 && data.status_reason === "Domain name is not registered") {
                return { ...data, not_registered: true };
            }
            if (data.status !== 1) {
                return { error: data.status_reason || `API returned status ${data.status}`, status: data.status };
            }
            return data;
        } catch (error) {
            return { error: `Network error: ${error.message}`, status: 0 };
        }
    }

    /**
     * Calculates a human-readable age string from a creation date.
     * @param {string} creationDateStr - The date string from the WHOIS record.
     * @returns {string} - A formatted age string (e.g., "2 yrs", "5 mos").
     */
    function calculateDomainAgeString(creationDateStr) {
        if (!creationDateStr || creationDateStr === 'N/A') return 'Unknown';
        const creationDate = new Date(creationDateStr);
        if (isNaN(creationDate.getTime())) return 'Invalid Date';

        const diffTime = new Date().getTime() - creationDate.getTime();
        if (diffTime < 0) return 'Future';

        const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
        if (diffDays < 30) return `${diffDays}d`;
        if (diffDays < 365) return `${Math.floor(diffDays / 30.44)}mo`;
        
        const years = Math.floor(diffDays / 365.25);
        return `${years}yr${years !== 1 ? 's' : ''}`;
    }

    /**
     * Calculates a numerical score (0-100) based on the domain's age.
     * @param {string} creationDateStr - The date string from the WHOIS record.
     * @returns {number} - A score from 0 (very new/risky) to 100 (very old/established).
     */
    function calculateDomainAgeScore(creationDateStr) {
        if (!creationDateStr || creationDateStr === 'N/A') return 20;
        const created = new Date(creationDateStr);
        if (isNaN(created.getTime())) return 5;

        const ageDays = (new Date().getTime() - created.getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays < 0) return 5;      // Future date
        if (ageDays < 30) return 10;    // Less than 1 month
        if (ageDays < 90) return 30;    // Less than 3 months
        if (ageDays < 180) return 50;   // Less than 6 months
        if (ageDays < 365) return 75;   // Less than 1 year
        if (ageDays < 730) return 90;   // Less than 2 years
        return 100;                     // 2+ years old
    }

    /**
     * Formats a date string into a consistent, readable format.
     * @param {string} dateInput - The raw date string.
     * @returns {string} - Formatted date (e.g., "Jan 1, 2023") or "N/A".
     */
    function formatDateForDisplay(dateInput) {
        if (!dateInput || ['N/A', '0000-00-00'].some(val => String(dateInput).includes(val))) return 'N/A';
        try {
            const date = new Date(String(dateInput).replace(/-/g, '/')); // More robust parsing
            if (isNaN(date.getTime())) return 'Invalid Date';
            return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
        } catch (e) {
            return 'Date Error';
        }
    }

    /**
     * Processes raw WHOIS data into a standardized object for the extension to use.
     * @param {object} rawData - Raw data object from fetchWhoisData.
     * @param {string} requestedDomain - The domain that was queried.
     * @returns {object} - A structured object with processed details.
     */
    function processWhoisDataForPopup(rawData, requestedDomain) {
        if (!rawData || rawData.error || (rawData.status !== 1 && !rawData.not_registered)) {
            return {
                error: rawData?.error || 'Unknown WHOIS processing error',
                domain_name: requestedDomain,
                domainAgeString: 'Error',
                domainAgeScore: 0,
            };
        }
        if (rawData.not_registered) {
            return {
                error: null,
                domain_name: requestedDomain,
                domainAgeString: 'N/A',
                domainAgeScore: 0,
                not_registered: true,
                formatted_create_date: 'Domain is not registered',
            };
        }

        const createDate = rawData.create_date;
        return {
            error: null,
            domain_name: rawData.domain_name || requestedDomain,
            create_date: createDate,
            registrar_name: rawData.domain_registrar?.registrar_name || rawData.registrar_name || 'N/A',
            domainAgeString: calculateDomainAgeString(createDate),
            domainAgeScore: calculateDomainAgeScore(createDate),
            formatted_create_date: formatDateForDisplay(createDate),
        };
    }

    /**
     * Updates the Domain Age metric UI in the popup with the processed data.
     * @param {object} ageData - The processed data object from processWhoisDataForPopup.
     */
    function updateDomainAgeMetricUI(ageData) {
        if (!elements.domainAgeProgress) cacheElements();
        if (!elements.domainAgeProgress) return;

        const { error, domainAgeString, domainAgeScore, formatted_create_date, not_registered } = ageData || {};
        const score = error ? 0 : domainAgeScore || 0;
        const displayAgeText = error ? 'Error' : not_registered ? 'N/A' : domainAgeString || '...';
        const titleText = error ? `WHOIS Error: ${error}` : `Registered: ${formatted_create_date || 'Unknown'}`;

        let color = 'var(--neutral-color)';
        if (error || not_registered) color = 'var(--danger-color)';
        else if (score < 20) color = 'var(--danger-color)';
        else if (score < 60) color = 'var(--warning-color)';
        else color = 'var(--safe-color)';

        window.updateProgressCircle?.(elements.domainAgeProgress, score, color);
        elements.domainAgeTextDisplay.textContent = displayAgeText;
        elements.domainAgeTextLabel.title = titleText;
    }
    
    /**
     * Resets the Domain Age metric UI to its default, initial state.
     */
    function resetUI() {
        updateDomainAgeMetricUI({ domainAgeString: '-', domainAgeScore: 0, formatted_create_date: 'Domain age details will appear here.' });
    }

    // --- Public API ---
    return {
        fetchAndDisplayDomainAge: async (domain, apiKey) => {
            const rawData = await fetchWhoisData(domain, apiKey);
            const processedData = processWhoisDataForPopup(rawData, domain);
            updateDomainAgeMetricUI(processedData);
            return processedData;
        },
        updateDomainAgeMetricUI: updateDomainAgeMetricUI,
        resetUI: resetUI
    };
})();