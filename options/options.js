/**
 * options.js - Manages the extension's settings page.
 * It handles loading, saving, and resetting API keys stored in chrome.storage.local.
 */

// --- DOM Elements Cache ---
// Caching DOM elements improves performance by reducing redundant queries.
const elements = {
  form: document.getElementById('settings-form'),
  googleKey: document.getElementById('google-api-key'),
  virustotalKey: document.getElementById('virustotal-api-key'),
  whoxyKey: document.getElementById('whoxy-api-key'),
  chatGptKey: document.getElementById('chatgpt-api-key'),
  saveBtn: document.getElementById('save-btn'),
  resetBtn: document.getElementById('reset-btn'),
  status: document.getElementById('status-message')
};

// --- State ---
let statusTimeout = null;

/**
 * Initializes the options page by loading settings and setting up event listeners.
 */
async function init() {
  // Gracefully exit if not running in the extension environment
  if (typeof chrome === 'undefined' || !chrome.storage) {
    console.warn("PhishGuard: Not running in a Chrome extension context. Options page will be non-functional.");
    setButtonsDisabled(true);
    showStatus('This page only works within the PhishGuard extension.', 'error');
    return;
  }
  await loadSettings();
  setupEventListeners();
  await loadTheme();
}

/**
 * Sets up event listeners for form submission and button clicks.
 */
function setupEventListeners() {
  elements.form.addEventListener('submit', handleSave);
  elements.resetBtn.addEventListener('click', handleReset);
}

/**
 * Loads all API keys and theme settings from chrome.storage.local and populates the input fields.
 */
async function loadSettings() {
  try {
    const settings = await chrome.storage.local.get([
        'googleApiKey', 'virustotalApiKey', 'whoxyApiKey', 'chatGptApiKey'
    ]);
    elements.googleKey.value = settings.googleApiKey || '';
    elements.virustotalKey.value = settings.virustotalApiKey || '';
    elements.whoxyKey.value = settings.whoxyApiKey || '';
    elements.chatGptKey.value = settings.chatGptApiKey || '';
  } catch (error) {
    showStatus('Failed to load settings. Please try again.', 'error');
    console.error('Settings load error:', error);
  }
}

/**
 * Handles the form submission event to save the API keys.
 * @param {Event} e - The form submission event.
 */
async function handleSave(e) {
  e.preventDefault();
  const settings = {
    googleApiKey: elements.googleKey.value.trim(),
    virustotalApiKey: elements.virustotalKey.value.trim(),
    whoxyApiKey: elements.whoxyKey.value.trim(),
    chatGptApiKey: elements.chatGptKey.value.trim()
  };

  setButtonsDisabled(true);
  showStatus('Saving...', 'info');

  try {
    await chrome.storage.local.set(settings);
    showStatus('Settings saved successfully!', 'success');
  } catch (error) {
    showStatus('Failed to save settings. Check browser permissions.', 'error');
    console.error('Save error:', error);
  } finally {
    setButtonsDisabled(false);
  }
}

/**
 * Handles the "Clear All" button click. Asks for confirmation before clearing all keys.
 */
async function handleReset() {
  if (!confirm('Are you sure you want to clear all API keys? This will disable advanced features.')) return;

  setButtonsDisabled(true);
  showStatus('Resetting keys...', 'info');

  try {
    const clearedSettings = {
      googleApiKey: '',
      virustotalApiKey: '',
      whoxyApiKey: '',
      chatGptApiKey: ''
    };
    await chrome.storage.local.set(clearedSettings);

    // Clear input fields
    elements.googleKey.value = '';
    elements.virustotalKey.value = '';
    elements.whoxyKey.value = '';
    elements.chatGptKey.value = '';

    showStatus('All API keys have been cleared.', 'success');
  } catch (error) {
    showStatus('Failed to reset keys.', 'error');
    console.error('Reset error:', error);
  } finally {
    setButtonsDisabled(false);
  }
}

/**
 * Displays a status message to the user (e.g., success, error, info).
 * @param {string} message - The message to display.
 * @param {'success'|'error'|'info'} type - The type of message, which controls the styling.
 */
function showStatus(message, type) {
  clearTimeout(statusTimeout);
  elements.status.textContent = message;
  elements.status.className = `status-message ${type}`;
  elements.status.style.display = 'block';

  // Automatically hide the message after a delay, unless it's an error.
  if (type !== 'error') {
    statusTimeout = setTimeout(() => {
      elements.status.style.display = 'none';
    }, 4000);
  }
}

/**
 * Disables or enables the form action buttons to prevent multiple submissions.
 * @param {boolean} disabled - True to disable the buttons, false to enable.
 */
function setButtonsDisabled(disabled) {
  elements.saveBtn.disabled = disabled;
  elements.resetBtn.disabled = disabled;
}

/**
 * Loads the user's preferred theme (light/dark) and applies it to the document.
 */
async function loadTheme() {
  try {
    const { theme = 'light' } = await chrome.storage.local.get('theme');
    document.documentElement.setAttribute('data-theme', theme);
  } catch (error) {
    console.error('Theme load error:', error);
    // Fallback to light theme on error
    document.documentElement.setAttribute('data-theme', 'light');
  }
}

// --- Initializer ---
document.addEventListener('DOMContentLoaded', init);