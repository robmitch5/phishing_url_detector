import logging
import re
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Tuple, Any
from urllib.parse import urlparse, unquote

import dns.resolver
import requests
import streamlit as st
import tldextract
import whois
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
TIMEOUT = 10
MAX_REDIRECTS = 5
MAX_URL_LENGTH = 100
SUSPICIOUS_TLD_FILE = "suspicious-tlds.txt"
KNOWN_SHORTENERS_FILE = "shortening_services.txt"
SUSPICIOUS_KEYWORDS_FILE = "suspicious-keywords.txt"

class URLAnalyzer:
    def __init__(self):
        self.session = self._create_session()
        self.suspicious_tlds = self._load_file(SUSPICIOUS_TLD_FILE)
        self.shortening_services = self._load_file(KNOWN_SHORTENERS_FILE)
        self.suspicious_keywords = self._load_keywords()

    @staticmethod
    def _load_file(filename: str) -> set:
        try:
            with open(filename, 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            logger.warning(f"File {filename} not found. Using default values.")
            return set()

    def _load_keywords(self) -> set:
        """Load suspicious keywords from file, filtering out comments and empty lines."""
        try:
            with open(SUSPICIOUS_KEYWORDS_FILE, 'r') as f:
                return {
                    line.strip().lower()
                    for line in f
                    if line.strip() and not line.startswith('#')
                }
        except FileNotFoundError:
            logger.warning("suspicious_keywords.txt not found. Using default keywords.")
            return {
                'login', 'signin', 'verify', 'secure', 'account',
                'password', 'banking', 'update', 'authentication'
            }

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = True
        session.timeout = TIMEOUT
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session

    def get_domain_info(self, url: str) -> Tuple[str, int, Dict[str, Any]]:
        """Enhanced domain information retrieval with DNS record checks."""
        try:
            domain = urlparse(url).netloc
            ip_addresses = []

            # Parallel DNS lookups
            with ThreadPoolExecutor() as executor:
                a_future = executor.submit(dns.resolver.resolve, domain, 'A')
                mx_future = executor.submit(dns.resolver.resolve, domain, 'MX')

                try:
                    ip_addresses = [str(ip) for ip in a_future.result()]
                except Exception as e:
                    logger.error(f"DNS A record lookup failed: {e}")

                try:
                    mx_records = [str(mx) for mx in mx_future.result()]
                except Exception as e:
                    logger.error(f"DNS MX record lookup failed: {e}")
                    mx_records = []  # Initialize as an empty list if lookup fails

            # Enhanced WHOIS lookup with age calculation
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = min(creation_date)

                domain_age = (datetime.now() - creation_date).days if creation_date else None

                return ip_addresses if ip_addresses else None, 1, {
                    'IP Addresses': ip_addresses,
                    'Domain': domain,
                    'Domain Age (days)': domain_age,
                    'Creation Date': str(creation_date),
                    'Expiration Date': str(domain_info.expiration_date),
                    'Updated Date': str(domain_info.updated_date),
                    'Registrar': domain_info.registrar,
                    'MX Records': mx_records,
                    'Nameservers': domain_info.name_servers,
                    'Registrant': domain_info.org,
                    'Domain Status': domain_info.status
                }
            except Exception as e:
                logger.error(f"WHOIS lookup error: {e}")
                return ip_addresses if ip_addresses else None, 0, {}

        except Exception as e:
            logger.error(f"Domain info retrieval error: {e}")
            return None, 0, {}

    def _check_suspicious_keywords(self, url: str) -> dict:
        """Analyze the URL for suspicious keywords and return detailed analysis."""
        url_lower = url.lower()
        found_keywords = [keyword for keyword in self.suspicious_keywords if keyword in url_lower]

        # Define high-risk keyword combinations
        high_risk_combinations = [
            ('verify', 'account'),
            ('confirm', 'password'),
            ('login', 'secure'),
            ('update', 'billing'),
            ('suspicious', 'activity')
        ]

        high_risk_found = [
            f"{combo}-{combo}"
            for combo in high_risk_combinations
            if all(word in url_lower for word in combo)
        ]
        risk_score = len(found_keywords) + (len(high_risk_found) * 2)
        return {
            'found_keywords': found_keywords,
            'count': len(found_keywords),
            'high_risk_combinations': high_risk_found,
            'risk_score': risk_score
        }

    def check_url_heuristics(self, url: str, subdomain: str, domain: str,
                             suffix: str) -> Tuple[Dict[str, bool], int]:
        """Enhanced heuristic checks with additional security indicators."""
        heuristic_results = {}
        score = 0

        # Decode URL for better analysis
        decoded_url = unquote(url)

        # Updated check for suspicious keywords to return a boolean value
        checks = {
            "IP Address in URL": (re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded_url) is not None, 10),
            "Excessive Length": (len(decoded_url) > MAX_URL_LENGTH, 5),
            "URL Shortener": (any(service in decoded_url.lower() for service in self.shortening_services), 10),
            "@ Symbol": ("@" in decoded_url, 10),
            "Double Slashes": ("//" in decoded_url.replace("://", ""), 5),
            "Suspicious TLD": (suffix.lower() in self.suspicious_tlds, 8),
            "Multiple Subdomains": (subdomain.count(".") > 1, 5),
            "Domain Hyphens": (domain.count("-") > 1, 5),
            "Numeric Domain": (bool(re.search(r'\d{4,}', domain)), 5),
            "Suspicious Keywords": (self._check_suspicious_keywords(decoded_url)['count'] > 0, 8),
            "Special Characters": (bool(re.search(r'[<>{}|\[\]~]', decoded_url)), 7),
            "Data URI Scheme": (decoded_url.startswith("data:"), 10),
            "JavaScript Protocol": (decoded_url.lower().startswith("javascript:"), 10)
        }

        # Process all checks
        for check_name, (condition, weight) in checks.items():
            heuristic_results[check_name] = condition
            if condition:
                score += weight

        # Enhanced keyword checking with detailed analysis
        keyword_analysis = self._check_suspicious_keywords(url)
        heuristic_results["Suspicious Keywords"] = keyword_analysis['count'] > 0
        heuristic_results["Suspicious Keyword Details"] = {
            'Keywords Found': keyword_analysis['found_keywords'],
            'High Risk Combinations': keyword_analysis['high_risk_combinations']
        }
        score += keyword_analysis['risk_score'] * 2

        # Check SSL certificate
        ssl_status = self._check_ssl_certificate(url)
        heuristic_results["Invalid SSL"] = not ssl_status
        if not ssl_status:
            score += 10

        # Check for redirects
        redirect_count = self._check_redirects(url)
        heuristic_results["Excessive Redirects"] = redirect_count > MAX_REDIRECTS
        if redirect_count > MAX_REDIRECTS:
            score += 5

        return heuristic_results, score

    def _check_ssl_certificate(self, url: str) -> bool:
        """Verify SSL certificate validity."""
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return False
                
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return bool(cert)
        except Exception as e:
            logger.error(f"SSL certificate check failed: {e}")
            return False

    def _check_redirects(self, url: str) -> int:
        """Check number of redirects for a given URL."""
        try:
            response = self.session.head(
                url,
                allow_redirects=True,
                timeout=TIMEOUT
            )
            return len(response.history)
        except Exception as e:
            logger.error(f"Redirect check failed: {e}")
            return 0

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main analysis method."""
        try:
            start_time = time.time()
            
            # Extract URL components
            extracted = tldextract.extract(url)
            subdomain, domain, suffix = extracted.subdomain, extracted.domain, extracted.suffix
            
            # Get domain information
            ip_address, whois_score, whois_info = self.get_domain_info(url)
            
            # Check URL heuristics
            heuristic_results, score = self.check_url_heuristics(url, subdomain, domain, suffix)
            
            # Calculate final risk score
            final_score = score + (10 if not whois_score else 0)
            
            analysis_time = time.time() - start_time
            
            return {
                'URL': url,
                'Subdomain': subdomain,
                'Domain': domain,
                'Suffix': suffix,
                'IP Address': ip_address,
                'Risk Score': final_score,
                'Analysis Time': f"{analysis_time:.2f}s",
                'Heuristic Results': heuristic_results,
                'WHOIS Information': whois_info
            }
            
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            raise

def main():
    st.set_page_config(
        page_title="Advanced Phishing URL Detector",
        page_icon="🔍",
        layout="wide"
    )

    st.title("🔍 Advanced Phishing URL Detector")
    
    # Sidebar configuration
    st.sidebar.header("Analysis Configuration")
    
    # Advanced options in sidebar
    with st.sidebar.expander("Advanced Options"):
        timeout = st.slider("Request Timeout (seconds)", 5, 30, TIMEOUT)
        max_redirects = st.slider("Max Redirects", 1, 10, MAX_REDIRECTS)
        check_ssl = st.checkbox("Check SSL Certificate", value=True)
        check_dns = st.checkbox("Check DNS Records", value=True)

    # Main content
    st.markdown("""
    ### About This Tool
    This advanced URL analyzer helps detect potential phishing URLs using multiple security checks:
    - Domain age and registration details
    - SSL certificate validation
    - DNS record analysis
    - URL pattern recognition
    - Known malicious indicators
    
    ⚠️ **Disclaimer**: This tool is for informational purposes only. Always exercise caution with suspicious URLs.
    """)

    # URL input
    url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    
    if st.button("Analyze URL", key="analyze_button"):
        if not url:
            st.warning("Please enter a URL to analyze.")
            return
            
        try:
            # Initialize analyzer
            analyzer = URLAnalyzer()
            
            # Show progress
            with st.spinner("Analyzing URL..."):
                # Perform analysis
                results = analyzer.analyze_url(url)
                
                # Calculate risk level
                risk_score = results['Risk Score']
                if risk_score >= 40:
                    risk_level = "High Risk 🔴"
                    risk_color = "red"
                elif risk_score >= 20:
                    risk_level = "Medium Risk 🟡"
                    risk_color = "orange"
                else:
                    risk_level = "Low Risk 🟢"
                    risk_color = "green"

                # Display results in columns
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"### Risk Assessment")
                    st.markdown(f"**Risk Level:** <span style='color:{risk_color}'>{risk_level}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Risk Score:** {risk_score}")
                    st.markdown(f"**Analysis Time:** {results['Analysis Time']}")
                    
                    st.markdown("### Basic Information")
                    st.json({
                        'Domain': results['Domain'],
                        'Subdomain': results['Subdomain'],
                        'TLD': results['Suffix'],
                        'IP Address': results['IP Address']
                    })

                with col2:
                    st.markdown("### Security Indicators")
                    heuristic_display = {k: v for k, v in results['Heuristic Results'].items() 
                                          if not isinstance(v, dict)}
                    security_indicators = pd.DataFrame(
                        heuristic_display.items(),
                        columns=['Indicator', 'Status']
                    )
                    st.dataframe(security_indicators.style.applymap(
                        lambda x: 'background-color: #ffcccc' if x == True else 'background-color: #ccffcc',
                        subset=['Status']
                    ))

                # Keyword analysis section
                if results['Heuristic Results'].get('Suspicious Keyword Details'):
                    with st.expander("Keyword Analysis"):
                        keyword_details = results['Heuristic Results']['Suspicious Keyword Details']
                        if keyword_details['Keywords Found']:
                            st.warning("Suspicious Keywords Found:")
                            st.write(keyword_details['Keywords Found'])
                        if keyword_details['High Risk Combinations']:
                            st.error("High Risk Keyword Combinations:")
                            st.write(keyword_details['High Risk Combinations'])

                with st.expander("WHOIS Information"):
                    st.json(results['WHOIS Information'])
                
                with st.expander("Technical Details"):
                    st.markdown("### URL Analysis Details")
                    st.code(f"""
Full URL: {url}
Protocol: {urlparse(url).scheme}
Path: {urlparse(url).path}
Query Parameters: {urlparse(url).query}
                    """)
                
                with st.expander("Raw Analysis Data"):
                    st.json(results)

                # Recommendations
                st.markdown("### Recommendations")
                if risk_score >= 40:
                    st.error("""
🚨 **High Risk Detected**
- Do not proceed to this website
- Do not enter any personal information
- Report this URL to relevant authorities
                    """)
                elif risk_score >= 20:
                    st.warning("""
⚠️ **Exercise Caution**
- Proceed with extreme caution
- Verify the website's legitimacy through other means
- Do not enter sensitive information without verification
                    """)
                else:
                    st.success("""
✅ **Seems Safe**
- URL appears to be legitimate
- Still exercise normal web safety practices
- Report any suspicious activity
                    """)

        except Exception as e:
            st.error(f"An error occurred during analysis: {str(e)}")
            logger.error(f"Analysis error for URL {url}: {str(e)}", exc_info=True)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        st.error(f"Application error: {str(e)}")
        logger.critical("Application error", exc_info=True)