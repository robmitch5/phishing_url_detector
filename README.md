# Advanced Phishing URL Detector

An advanced URL analysis tool built with Python and Streamlit to help detect potential phishing websites. The tool uses a combination of DNS lookups, WHOIS information, SSL certificate validation, and heuristic URL checks to assess the risk of a given URL.

## Overview

This tool analyzes a URL by:

* **DNS Analysis:** Performs parallel A and MX record lookups to retrieve IP addresses and mail exchange servers.
* **WHOIS Lookup:** Retrieves domain registration details and calculates the domain age.
* **Heuristic Checks:** Evaluates various URL features (e.g., use of IP addresses in the URL, excessive URL length, suspicious keywords, etc.) to generate a risk score.
* **SSL Validation:** Checks the validity of the SSL certificate.
* **Redirect Analysis:** Monitors the number of redirects the URL initiates.

Based on the analysis, the tool provides:

* A risk score and risk level (Low, Medium, High)
* Detailed security indicators and technical details
* Recommendations for further action

**Disclaimer:** This tool is for informational purposes only. It should not be solely relied upon to determine the safety of a website.

## Features

* **Comprehensive URL Analysis:** Leverages multiple security checks, including DNS, WHOIS, and SSL validation.
* **Heuristic Risk Scoring:** Uses URL characteristics and known suspicious keywords to calculate a risk score.
* **Interactive Web Interface:** Built with Streamlit for a user-friendly experience.
* **Parallel Processing:** Uses Python's `ThreadPoolExecutor` for faster DNS lookups.
* **Customizable Settings:** Users can adjust request timeout and maximum redirects and enable/disable SSL or DNS checks.

## Installation

### Prerequisites

* Python 3.7 or later
* `pip` (Python package installer)

## Required Files

The tool relies on several optional configuration files for additional data:

* `suspicious_tlds.txt`: A list of top-level domains flagged as suspicious.
* `shortening_services.txt`: Known URL shortening services.
* `suspicious-keywords.txt`: Keywords that may indicate phishing.

Place these files in the same directory as the main script (`phishing_url_detector.py`). If these files are absent, the tool will use default values and display a warning in the logs.

## Usage

To run the application, execute the following command from your terminal:

```bash
streamlit run phishing_url_detector.py
