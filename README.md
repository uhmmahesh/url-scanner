# Cyber URL Scanner

Offline, heuristic URL scanner with a cyberpunk console UI.

## Running the scanner

- **Option 1 – Double-click**: Open `index.html` in any modern browser (Chrome, Edge, Firefox, Brave).
- **Option 2 – Simple static server**:
  - On Windows with Python installed:
    - Run `python -m http.server 8000` inside this folder.
    - Open `http://localhost:8000` in your browser.

No backend or external services are required; everything runs locally in the browser.

## What it does

- **URL Information**: Shows protocol, hostname, path, query string, URL length, TLD, subdomains, and whether the host is an IP address.
- **Threat Indicators**: Uses static rules to flag risky properties such as missing HTTPS, raw IP hosts, suspicious TLDs, shortening services, very long URLs, `@` symbols, phishing-like keywords, and punycode.
- **Spoof Detection**: Performs a simple similarity check against a small set of popular brands to highlight possible look‑alike domains or embedded brand names.
- **Risk Score**: Aggregates findings into a 0–100 score and a qualitative label (low / medium / high) with a visual meter and factor list.
- **Summary**: Generates a concise, human‑readable security summary in a cyber‑style tone.

## Important note

This tool is **heuristic only**:

- It does **not** contact the target URL or execute any remote code.
- It does **not** guarantee that a URL is safe or unsafe.
- Always combine the output with your own judgement and other security tools.

