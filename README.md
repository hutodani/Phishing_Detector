# Phishing URL & Domain Impersonation Detector

A Python-based security tool designed to identify malicious links, brand impersonation, and typo-squatted domains.

## Features
- **Typo Detection:** Compares domain names against legitimate brands to spot lookalike spellings and character swaps.
- **Subdomain Inspection:** Uses domain parsing to detect fake brand names placed in subdomains.
- **Automated URL Checking:** Evaluates target URLs against known legitimate brand lists to flag suspicious links.

## Tech Stack
- Python
- `tldextract`
- `Levenshtein`
