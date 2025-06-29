# phising-site-detection-browser-extension
A browser extension that can detect whether a website is a phishing or malicious site.

Here's your well-formatted `README.md` with improved grammar, structured clarity, and **no asterisks or markdown decorations**, so it reads cleanly even as plain text:

---

# PhishGuard - Advanced Phishing & Malware Detection Extension

PhishGuard is a powerful browser extension that provides multi-layered defense against phishing, malware, and other malicious websites. It goes beyond basic blocklists by performing real-time, in-depth analysis of any URL to generate a comprehensive risk score and a human-readable summary.

---

## Table of Contents
* What is PhishGuard
* Key Features
* Why Use PhishGuard
* How It Works
* API Integrations
* Setup and Installation
* Project File Structure
* Contributing
* License

---

## What is PhishGuard

PhishGuard is a Chrome extension built to help users identify and avoid online threats. When a URL is checked, either manually or by scanning the current browser tab, the extension runs several verification steps against top-tier security APIs. It then calculates a risk score and generates a clear, AI-written summary of the findings.

---

## Key Features

[Full UI]![Screenshot 2025-06-29 111613](https://github.com/user-attachments/assets/140584e2-13e6-4432-b049-1cdcff9fef5c)![Screenshot 2025-06-29 111631](https://github.com/user-attachments/assets/90bee5ff-db92-47f3-aba4-a475e1f322ed)![Screenshot 2025-06-29 111640](https://github.com/user-attachments/assets/ad1c1ead-c46a-4519-80b5-f637a2e6f533)![Screenshot 2025-06-29 111648](https://github.com/user-attachments/assets/2da42479-63f2-48de-a612-b4388448fef5)![Screenshot 2025-06-29 111659](https://github.com/user-attachments/assets/f9b3aa9f-76c2-42bb-8949-6c1fe06c63c5)![Screenshot 2025-06-29 111711](https://github.com/user-attachments/assets/1432d5fa-169b-4478-8818-cf6a8c84fa34)![Screenshot 2025-06-29 111739](https://github.com/user-attachments/assets/60ae9f3e-4185-492e-aa61-bb6f17302b10)








* Comprehensive risk score based on multiple data sources
* Checks Google Safe Browsing, VirusTotal, domain age, and SSL status
* Uses Mistral 7B AI model to generate concise summaries from metadata
* Highlights phishing-related indicators like suspicious keywords and TLDs
* Tracks scan history for the most recent 20 sites
* Built-in light and dark themes

---

## Why Use PhishGuard

Traditional antivirus and browser blocklists are reactive. PhishGuard adds a proactive layer of defense by analyzing URLs not yet flagged elsewhere. Ideal for:

* Users needing a second opinion on suspicious links
* Catching newly registered or obscure phishing domains
* Learning to identify threats by understanding the reasoning

---

## How It Works

The extension performs the following steps during a scan:

1. Accepts a user-provided URL or fetches the current browser tab URL
2. Checks if results are cached from the last 5 minutes
3. Retrieves all API keys securely from chrome storage
4. Runs all API checks in parallel, including:

   * Google Safe Browsing
   * VirusTotal
   * WHOIS domain age
   * SSL certificate
   * URL keyword and TLD analysis
5. Sends the metadata to an AI model (Mistral 7B via OpenRouter)
6. AI generates a summary including impersonation risk and key red flags
7. A final risk score is calculated
8. Results are rendered in the UI and cached for future lookups

---

## API Integrations

PhishGuard integrates with top APIs to ensure robust and accurate checks.

Google Safe Browsing
Provides real-time URL threat checks based on malware, phishing, or unwanted software lists.

VirusTotal
Scans URLs using over 70 antivirus engines and returns malicious or suspicious hit counts.

Whoxy WHOIS
Retrieves domain registration details such as age and registrar.

OpenRouter (Mistral 7B AI)
Translates complex security data into human-readable summaries by simulating a security analyst.

---

## Setup and Installation

### Prerequisites

* A modern browser (Chrome, Edge, Brave)
* API keys for Google Safe Browsing, VirusTotal, Whoxy, and OpenRouter

### Installation Steps

1. Clone the repository

```
git clone https://github.com/your-username/phishguard.git  
cd phishguard  
```

2. Load the extension into your browser

* Go to your browser’s extensions page
* Enable Developer Mode
* Click "Load unpacked" and select the `phishguard` folder

---

## API Key Configuration

You must manually set your API keys in Chrome's local storage.

### Get the Keys

* Google: From Google Cloud Console
* VirusTotal: From your profile on virustotal.com
* Whoxy: From your Whoxy account
* OpenRouter: From openrouter.ai

### Set the Keys

Open the extension’s background console and run this:

```javascript
chrome.storage.local.set({
  googleApiKey: 'YOUR_GOOGLE_KEY',
  virustotalApiKey: 'YOUR_VIRUSTOTAL_KEY',
  whoxyApiKey: 'YOUR_WHOXY_KEY',
  chatGptApiKey: 'YOUR_OPENROUTER_KEY'
}, () => {
  console.log('PhishGuard API keys have been set successfully!');
});
```

---

## Project File Structure

phishguard/
├── popup.html – HTML layout for the extension UI
├── popup.css – Styling for themes, layout, and components
├── popup.js – Core logic for scanning and displaying results
├── whois.js – Utility for handling WHOIS lookups
├── manifest.json – Extension configuration and permissions
├── icons/ – Folder containing extension icons
└── README.md – This file

---

## Contributing

All contributions are welcome. Submit issues, feature suggestions, or pull requests via GitHub.

---

## License

This project is licensed under the MIT License.

---

Let me know if you want the markdown version too or a live badge/readme template for GitHub.

---

MIT License

Copyright (c) \[2025] \[Manish Mohan Singh]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


Project File Structure
Generated code
phishguard/
│
├── popup.html          # The HTML structure for the extension popup.
├── popup.css           # All styles for the popup UI, including themes and animations.
├── popup.js            # The core logic: event handling, API calls, UI updates, risk scoring.
├── whois.js            # (Assumed) A helper script for handling the Whoxy API call and its UI component.
├── manifest.json       # The extension's manifest file, defining permissions and structure.
├── icons/              # Directory for the extension icons (16x16, 48x48, 128x128).
└── README.md           # This file.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END
Contributing

Contributions are welcome! If you have suggestions for new features, improvements, or bug fixes, please feel free to open an issue or submit a pull request.

License

This project is licensed under the MIT License.
